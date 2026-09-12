<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Discovers and wires up modules under includes/modules/*.
 * Each module dir has a module.php defining a class WPOpsec_Module_<Name>
 * with static activate(), deactivate(), register() methods.
 */
class WPOpsec_Module_Loader {

	/**
	 * Base64-embedded so the dashboard header has no external asset
	 * dependency to resolve a URL for, matching dashboard_styles()' own
	 * inline-CSS reasoning. Shield-and-checkmark mark supplied for the
	 * project; small enough (~12KB) that inlining costs nothing real.
	 */
	const LOGO_PNG_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAAtGVYSWZJSSoACAAAAAYAEgEDAAEAAAABAAAAGgEFAAEAAABWAAAAGwEFAAEAAABeAAAAKAEDAAEAAAACAAAAEwIDAAEAAAABAAAAaYcEAAEAAABmAAAAAAAAAGAAAAABAAAAYAAAAAEAAAAGAACQBwAEAAAAMDIxMAGRBwAEAAAAAQIDAACgBwAEAAAAMDEwMAGgAwABAAAA//8AAAKgBAABAAAAZAAAAAOgBAABAAAAZAAAAAAAAADVwxdQAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAFV2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI2LTA5LTAzPC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkRhdGE+eyZxdW90O2RvYyZxdW90OzomcXVvdDtEQUhVSWtLQVYwYyZxdW90OywmcXVvdDt1c2VyJnF1b3Q7OiZxdW90O1VBQ0ozMXdMTlZnJnF1b3Q7LCZxdW90O2JyYW5kJnF1b3Q7OiZxdW90O8OJcXVpcGUgZGUgbmllbWUgY29uc2VpbCZxdW90O308L0F0dHJpYjpEYXRhPgogICAgIDxBdHRyaWI6RXh0SWQ+MjVjNDE5MDgtZmZkMy00MmUyLTliMzYtZDA4NzFkOWNhNTE5PC9BdHRyaWI6RXh0SWQ+CiAgICAgPEF0dHJpYjpGYklkPjUyNTI2NTkxNDE3OTU4MDwvQXR0cmliOkZiSWQ+CiAgICAgPEF0dHJpYjpUb3VjaFR5cGU+MjwvQXR0cmliOlRvdWNoVHlwZT4KICAgIDwvcmRmOmxpPgogICA8L3JkZjpTZXE+CiAgPC9BdHRyaWI6QWRzPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpkYz0naHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8nPgogIDxkYzp0aXRsZT4KICAgPHJkZjpBbHQ+CiAgICA8cmRmOmxpIHhtbDpsYW5nPSd4LWRlZmF1bHQnPlNlY3VyaXR5IC0gNTwvcmRmOmxpPgogICA8L3JkZjpBbHQ+CiAgPC9kYzp0aXRsZT4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6cGRmPSdodHRwOi8vbnMuYWRvYmUuY29tL3BkZi8xLjMvJz4KICA8cGRmOkF1dGhvcj5uaWVtZSBjb25zZWlsPC9wZGY6QXV0aG9yPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczp4bXA9J2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8nPgogIDx4bXA6Q3JlYXRvclRvb2w+Q2FudmEgZG9jPURBSFVJa0tBVjBjIHVzZXI9VUFDSjMxd0xOVmcgYnJhbmQ9w4lxdWlwZSBkZSBuaWVtZSBjb25zZWlsPC94bXA6Q3JlYXRvclRvb2w+CiA8L3JkZjpEZXNjcmlwdGlvbj4KPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KPD94cGFja2V0IGVuZD0ncic/PhnDUhoAAB4tSURBVHic7V13eFvXdQdEyZIt24ktO8OJE6d1E6f50sRp80f75YvT5GvrtLVsyaaWV2zHqZM0cdMMS6IoUJKtWrYlWxYXBgcoapjWIEFMLnABIEhwD4DgkETtvQdFAqf33PHwMDjkyAKl4Hx6AgmCxHv3937n/M65514oFAlLWMISlrCEJSxhCUtYwhKWsIQl7FMyUCjJ/0pVV/JtKpViWrxP5y/agIGhUO1J/sLSnoVfZ0+y5xJ2o40P/B+9c+9a4U1eotrz4qx4n9INM5VKNQ0AptadB8w9rehdmLK8Z8H38Gs8z/ie1I0wfpEIyFQBpQiSk/BxpTf5j6m+BX/Cr5OL2HO3tCUD0ItMLrJ84w1D3VfY10VxvXCV/bHp+LiiO3nBCu+Cyniey400JblyeuHfyin9zgO5lmPvWx1dZfXND+BzKjv72Y22Is4CVW/ydwkzjqzwL3qUfg+3sqsibukxPuCP6ow/vCPHcvI2nQVyalpBX+H2Z1rqv4E/o6DcQBcm4sOv3U/NWb1vyR7V4KIV+L1wX7ekUXfEL/xLmtJXb9dZhhUaE9yhNgQ2WRyjW2pbILey8YTWXPcEvqaoCJJUAJ/+3SnkLckzVH2L6lcPLWmiT0+RmHb9DS+Mu6i8PPusL6hL85LyK0ChNo0qMksCd6hLIcPmhLwyZyC/silYUN0MGkvdCv7byiIeaz4tE64qrX+R+s0Dz8IbbU/fwq4KWcED9Xdzzd+/W2vsmKavAgLE6LQsQ1CRUQJ3ZRtgk9UBuWUu0NkcwdwK9+hWRydobY7yPIvrIfZnipLgU2CLCOKoptaffxlW9i9Mxe+TbzlXhYPHgQA7TH9Aa0yZmWO9osixMTCyS0GZWQKKTbtB7z8Aew4dh2xLPegIKASYoK7MObq1vgNyy90nNabqF8SfRWCulxsTYCwjiurtYy/AqsFF7sfNj89k53+rZOQqAQTzv4/kmv7lbrWxnbIi20hdVBIBQ5FeDEkZxaDv3Q/Ceg8cBY3VSZjhJEA04OMourDC2jbQWh02rdn1d/g30bdzxnziQRPBemnHU/+4amDxxbSBxZDSlfwDfO7WyDkIEDRo80F6VG/85hxNyY4ZuYQRnBWEEcHpaiMoPtwF9+VawDJ0lAIxEggC+Udt6NgpKKhspGzJq2iAnDJXgLCGsiW/ovEyiS0b0o32L+B7MGDgmoERA760Y/5fkbgx+O6pF4G4rHfkP7t5LRQj6KD867aaBz+nMWTO0pquKPMrQZFVOqrIYqyYnmUAxQc74R921IL/zAUGRjAIQXoAfUQ7feES7Ha2Q6apjjIFD3RheRXuwDZnF4J0XGd1vKErrr8L31MAMxlXJgqGv+pKvnNl70LnuhMvQlr/wnaV//G72QtuSldF7kjME5iEZUDk7n7wi5rSDberjeeU1D2VBhSZBhIrDJBEVBTGCjxed3TBpZFROvCjhBZBCBl+LUAZGQ2A0ztImaIhAT+vHNniDOrQjVU1BREYndW5T2dxvZ5u77pTnBmCMo4qU4p8Q9W/aPvaQ88BeYSUvuTH8bmbLedQKlgeMV36nti3N1u+93mdUX27pvQsA8KIymlUSRQUAjENAzdhxSPbq8Cyj7moQDBIDzH4J85dhMOnzzFQBFs4SHuJCyuqa4VMcx0N+AwY4sYIMHq7hwFT5hzUljcsy7U2PkjPjLswTC7lrBHKiTBj3Zv7nwWUuKl9izLpa28KiQucCRH1peQi+51/nW994bPqEvttWlNAAiKrZESZyYFA97RxJ9ylNcGaZj9cFKwIsngR4GAcP3sBCu1N1C0dOHEmBIqMLVdHR6G5f4iCkWWuhxzuxigwVkegwO4B6spsrnMEnM26MsdP5OUXdGmqLtVt+HWKL/mXa/YtIYpqMaQNLupb1pJ8P3vN1HRVSgqCWj1DEVFqBnKB38qz/Oh+TWn2HdmGo0n55aDIJQfmEpkhRigpELtASRRUcpkHBs5e4KxgYARlzNh/4jSWS4iCYspKZ3NB38HjHBSQXivYgrGlrMVHXVg2AiNjDCqyvIpGCoy+yoOqrENb5kpRWx2PiJm+5d1P/zRtcPGIyr8o+OYQcVe9C+fj81PPVaEbilFlRSZ8M8e44B6t8YPPqA1907XmIJWvahNgfFDSGFHKYgS6JsIIdFH/aXZD3aGTUlwIRARttO59hwkACISDqqmiuhY6wGoSMzx9QxDgsiv0u6FYc/DkGbA291AQkTE0d2HA0BiTY3MGN9e0EHA60Z2N5FlaKjfW6NPS9iQfXDWwBFbvWwzL/f+Rza4xOclObraiOFeZYxpmwo9qrQ9/Jcf0689qDR8TJpxOyrEFlQV2UGgtOOjIhhHMsKdjYsfzCYwRdxDX9FxlM7iPnpYGLhQrQjHh/KUrUNbqY66HJYFkMF1gauqCkoZOCg6qq1J3J4ktF8KCvZxdaEdI3Klq99Pfwb+HzBGqLNfmJHLZMZpX3gQF9Y2wYf+fIG0gOZDqSw6u8r0EGfaPX7MVwOwpp6rQv34xx/zKbLUxf47G2E2k6fB0ZAGrNaFLChAmXCVqKTAdYwOCkFECSgICqqaHt1bCqqZe2EMCs5wRVEHJBhC/79p7CAqqGung8TtaCtRmTzc5esBAgNhsb+SxwgWN/n0wzOPPWMCcuXgJmvxD8FFtM2GYg/4uMi+nrAHjSvCt9j+Mpvjnjqz0Lg6m9s2DjY4c0Je3k/euP6mzOUxEva0nrJoXbyTonfH7goLZ9+rLjykKa0GhsQQVbMCxzjRKWBCkWTXGBcIEAcL9+VZ4vrIFjHuPwGUiT0OMEEE7fMAOnToLxQ0dfKCcEhgCkHwSR2zNXjA2MVCQLR9xF5ZB2ILubPDICZBbULyP7Lmr5Fz2HD0JdsIaBD7P1gzvNK+BFX1Pgsq3BFL758G6tuXk+SaU0JBPEtDC2rbgzuZ+IMJg7+/Wr79dPjZxAeQXBsMd92hMexW0tmQYJbEhSAHIYHIVAzQqpq9tqYBXq9ugqP8gnLpyNWxwEITRCBDQUMqWE/eEIOCdS10JB0ICxMYAwdchICZ+WAgw6MK2VHtAjUGcxJZSdxfsOXIy7H1CMUr+3gEIkFP8qE8PS31zSfBeDCv9C2B55xLYZDOT/MUtcpogyWVG8lBY2Jy+jWbzzLgDsr7Iefu9WuM+hcaMxb6gkoPxQEEZvEIAyO7eA55jZ2BYxgQBwkggIMnXEEsCMHT8FB1QEXRzQkE36sDArq90Q2VbLxgbuyRATJwteOwiWbtwdXgUuzrAf/AYXLk6EsWakQBzb93nXbCy72kgOQcFZHnvk2DetwscHQegsLqRvi8/h0BBdQt+36VWe2bEDxBe/Muz22fN0RoHFVozSlZW+COsSO/cQy9sJBAacIwD6BYiQUA7SQJwE/H3H9e3gsbC7mgmS6NBiAQEa1f2Dn8UIHK24ONORxsFJpvGiTqav9R29VPVxeQxO6+hS34KQorvGVjlfxbe8M6F/P1rpHPt2ncoFMdI8EdFRqR3i0xpxQ8QM6EpCeZ9qKJCgOwkgAzSk7/MAYiEAJ87duY8tA0coAOJriiL+Hu50hkPiDBAyCDXdPZB6RiAyBmDjxiPttc006CfYayj7rCovhkavPvBe3QQ3ht4DZb75kOafzGs8CXDav9zcHR4SJJ6nURcZPE6GQOkFQFpkDEjfoCAB2bcpzH1CEBQzmLseL99IIohV4nawRK5o2cQdhAm6LhLUlvGd0sTAbKZAtI/ISByYJA1eCPsrG8jTEEXROSyuQZUrb+GlN55lCF4vOF9AupOlnCGM3fWvucgldZ5tGjpGsXyfo7VWSMbnLhIYQYISYru05R2KHRWBoiaAfJua78EiPBQJ4m0xbsxgzLBKYHwSYAQB8aZLdXM9UwWkHBwGEBGtxfWd64kiuopCYyl3idBN5TKQ39QcrWtA/spswQgW+ra8cYoiwcI0YCQZPB+ndETBsj7O2Bts5+xQgbIqfMXiSJq+LNBiARka40H6ro/GSDGpk6wNvVDVucHkILyFhUVCeQrexdAqnchDJzzMhcLodjX3I+A1IYAqaeAlPLxiFuiKABR3qc1OnESSZlVEpiBgGzYAWkk2ZMA4S4La0mYFaNUvR5gUEAI07aReFDfPUBl7bWCYWscgLz2AuqmVvYuCqkq/5PwgecDuHiRKzAIFTRRfGRILotNFZMbY8eUAATtfq2xWpFThgwZncEZktroiwLk7MXLNGe43oBghl1P4tK1AEKZQcDY2mqA1N5kcizggCyCFf6nYW33b0Bf1QAXLl+VABG5itu3V4ohJJMf2eboxMdCHAuV6ga0HU1kc3QmC63cksRQuKw/urpDMYQDcv7yFQ6I87oBgrEIM3HHNQCCYFia+mBHcw2k+Z6ngKg4O+hBksBCjwm2VLbBpeHhKECc5L3CAKFzKg4djkWci4yMnvdojLsVeeGAvF7fxZSJTPJevDJMk7jrC4iDTkA5vXvAQAAxTwgGvsYHBk8LrPX+Elb0zpfAYK5qLokn74PR5YcCu1uqg4EMEBQQmMfQqWECyHZy85GMPZ0B8un2gI1vfM7jMxrjFlpMFIAQlfVaTXsUIJgZYxJ3vQHBZNJFAemcABAEA3ORHniveymk+ENBXMVd1Vve16DU006y+U6q3nByKwQIe6wmOY9IDBGQjxpoVeFdOiRx6itmlszoeZfaoFFghTerZEQA8pK9jakTGSCYh2ASp71OgORyQDCnafBNDhBLYx982LU2DAwJkN6naUyxNQ3ATmcrbCexaSSi5IOGZZpsqeLsvFpEJDNhyGocC6l8Ehfj7Z0z1cb3FDjnkVkyIjL1JeXNUYCMkLtti73p+gPiaCOA7B0XEKGotB1qAsZTEWAspgBt6lxHAn0/yUu6aJkFmTcaiAbE1uKlpR3JZTGGLIs/IDhVi5ZVkqbYXIMu66qoZc2zNoaCoQCEXBzedaiMIqu2fw4gOHgNvWMDIhRVQdvHxC3NDwVvejBmvOl7FUo8zWBq9JIsvpuCgUXJWHU3fA81BcRFZS+qLJ3F8ToOhT2uLosDMivboFLKAflwFzxubAj5Xv6I06roXjS8D/e6AeJsA/cYgDAw+uGjljLOimQp3wgBMh82t+6gr6MKjGTuKBTw70UaXksJeZ5OB5S5pEw9t8z5cxyL+MYQDsh9GsOKpM3VIZf14W54rMQRBQiqFCzsaejcxlgD7eTH5AHZRQHZFwUIKioLSVB3e1ywxvcyZYJc3gpXtbFzDY0tGGNodbi5hzC5hf6tSEPG4A0gu6kCm6tb8JoW41jEV2Xxu+FLOuMb0zezGEKnaDfthu/vqJXoLic9FvTEZFM4CDhl6oZcWyM9Qs9PBpB2aIwCBBWVF0qb2mFdz+vEVc0LixvIjNTeZ2C17yUCmJtKYQGItdlLs3/sUIk0jCmY9+D70vOwOYP5VU2QbRNrUuKYh4iVTA/nml6fIZYIZLPp2r/dbidZeiAKELxYERDFoOfa3JBnbQZdeR2oqyygqawAnM/Os7aMC0wYIH45IGxgzY298H7XyihFxY7FtFyib9tK4wu6KsEsPEecacQGiMjzp8KkWhImQXoe2Nhtcf0o/oCIdX75lp/P4ImhAOSrheVweXQ06oIiJCNlg6bCDu81vguru18BlW8xOZ6FNzt/AxudGsyEKWCxQBGA7Ha10/qSAARdlSgYLo8BBnNVT8GG7lTq0gSAckCwpI8FS+FqhQ1fHZXnUsFcXmDMtTjZ0ucbsWJrLBMrXv++wJI8I8fKOkz4FO69uRY4z6dIWdmBXVAoy3VRMNRVNgLEq5DSN5cM1jO0ykorrUQNYXPB2rY/gbailrsxx4SAmDxM3ua26cmgzwsviUiuKpmWTHZ5HAQQX0xA8ivdVLmJuDFG+QcXB+HjFaIcH6aAxHUtugCk0PrPdJkAAUPJOhFhttYERy/xOpCsyQ0TuFAdyA1r239PB35l75Io9YN3Mv7szY7fElDsBJSmMKaEAdK3j6ifdgpGdMEwmh057fnEVQ2GuSo5IHh+LQP7Q4DIphB42R3PJZiHbClznd9U7p6DYwFxXVfI74ZHNKavT8s0DNPOEw7ITI1RWjIgGt7Q6OSOqQbyy1ogvW4bYcLTUYMWfiyhk0Zrun5FY0ue1SMxJQRIBzT27QFjQy/sbKmBVbEKhjIw1ncv5a4qdhKJsjefDLp36IjkssQNhZ0w4obQ8YCuszmOFNhss+MPCH/zezea756WZTiLjXEUEMIUjCWNvAtRDkjP0GHismpBb2uD9SRusJ6nyIAbeSBT5sHqrv+iLk6AkksCPwOkDTz+A7DL3RRVMJQzDl2higCMVV5Lo5/GmrFAQbeEPVqRgOw7doomthyUAC4wJcB0qz1x7TgJB+SxIvuds9WlJxggJawvi7DENnSMSUV5g/Tx06wflyiodz1vMXc1ISAClPmwqudlyLabqCrLKXeA2lpPC4HYz/t2xx+iyiJydmCA13ZoolRVVGZPpDkCcvj02ShAsH1IHcqj6Hy6zuaqlo1KPFtLZa1AGuMe2ptFArvIRTbz9X8jESX4/EribiytsMG9kcePyQDCAzJxcat6fgZZ1aWQZ8N8oA521XeDfvB9WOp7AtLGAAMD/Ds9/0srvRM1QJSQ5BWVFJ6rECWC4e2DB2QNDs7RrY4OjCXbcRymwuYy0t0wRzZryCq+O2CNh03jyjtP8E7DIKw1uyG7xsBV1WTACDEl1f8MqLzPQ0bNDsg3d8EHTR+SxC82M8T8+ErfIviopWJCV4VZOrah4jmGdTjGmC0UpXeSHH6AYxDfsokwnovcrjGuUxRUh1V8F5d5pBgiv6jargFyUbU0sL/XtA5S+p+Qpk+vhSlpPS+S338nNOgxXitclbojnSqw8VyVUFh6wo6arvAcRECDyWLUXIi1PgXHIL6VXm4iW/9ajun3MwrYnAh1Wem74dsfVUvskNPeu/+ILDlsIMH9PTrAeOdfm/taQIP9WK9hk07z4W3vbzgQPVE5R5TLIgfmGHiOckDEjRVZx8KgrrW6FuIYxLeOJYznIt+JkYvcqTPD4YtXJEDEpV24PBw2c4gBPr1uO4kNr/ABXjxJtkzMKqxXbWuxSJXc8cCw8D5gnGaWxw9hF69clU9BB1nzd8NVfVnzN3EMpkIMkZTWN3TFd83MMpwRSotl7MVQsvewpLTkZmvxcZawWhWqJk1FFfxf6zKad2CjweRd2Fiuai5kdG4grmpiMCR3RdQVrq6Sm2AJymCpqEjYobd7cKZwEEWNfCzibdJJ3KMx1dBF/lmhufVlbq+ktOQX149bYZjlRUYHrVlhNv6+K0OKE5N3YZGuis+PN7XRqu+Eroqwo5RXogcOHw87V/GIBczobhO3Hq9dFc8aVpTxeZE7NQbVND4vIqTv9z6ukdgRtgJD7o/L5WV4ZEsrZFYXk+z8NS6LryXgM1eGyeGW1pIJcw45OwpJ1o3nFMtwcg3dmYgfYmKK5FS/wGufGgpLGI8jD+XbfpikMYXiCHlMIkfzsTMSCPI7rvfgUamdJrySSxJHm4eW49c1r4JUkhCm+pMnxZbQ/PjbBAycdJoYDLEUDhnbd+hYTHYcOXOO169cofhR3nBJY2v4Gl771IgfkvGMPS9v1u3q0n66wFPWeC01zcWYnzYRNxE+PxJii5gn2ejIJXnHczRTHx8UZMYz0vz4ZFyVyD2QpZihR5oAxOXbIy1BEOzIq2i0xXvkxzaej8xWG96iq26p/GVzIw8WlMPp4VBLJrtQ9ogrZZmmj9X4wGYSUYXhxNVbHf/DAr6ksGKwg7gqbGaYjKoSYGyrbabncPr8pbBzE3aZnPvWao/ULUPONbClvgPzkJ+xS59K7koYp+wDGuN3SWI4QutZuBkAXy/yYQdbwBOZtaN104JjLJa4ZAG/iU5WYSIYnrMs4ssHlsAy/xOwsSt8fnwimYsdK+g2fQeOhp2T/GtcDxJKBp1BVFdE7u7daG6gG87AFFFX0cZPbKbOWqzIq+AziGwt+t8UVsA52YRV5EXjRjGSghmz+aGB5yxbIc37EmHLXOrGMHdZ1jsX1vX8DgyTdFUIBtsxqJZ2rESCIQy7LXF+XSvEh2gdLWugjXFTIxkcy3hwvzvX8m/TdFa2UQAGdl5KEYt4InMSMRhYlpgYFAfLWSorSIa/Hta2LoV321fClu6ttKHBHGMGMCYziJrC95JKJGPEDqwih/p42YRUXoX7WK61hm5UM3XZIYyf4Ayt2SoasJXZbFr3vhwz9J8NTVpFg8L6ZnGg2AYxY3WcOOiULrJFZ22AbfY2cHQeJEG5e3ww+KpcbNbDFVC1fM481s2BJhYY6fgsJe6Hst2F6yEbVHiNU3I7jSjj6yNmZpX+SEl3cpCzZBfMtbjHZIkwnI5F5RW5SUAsttA1hvZGqOrwjbkK18xZgdIW5znwb+Ni07HclHjG5OmWklcM5Fi30ld6vOqi8s/gNU59dgjjoCizSwsUrD1oRA7KOy199IJjyWAxQAOHT9DODxFMJ1qnXkHXqccGAoHCxjf8W9jCg7N+Y4IhrZIaihQadLWtrqx+Ll7b1I4dkSbunI07v6zQWPayvKSEdqTQI6MYSvcemRAU7PDAtiEsZ6jHWC4tdnIoaxVbazAQzBwIbGpDpiEr0B1eEvJ7nPfFsg6+p+w9RtjWgA0Z7PKmUplksib8a8bup3BBKNs70cA3nymGOToztJ5gU6RyKRw5OGi4HQbKU3XYhgINvNnZRdctYj6BYGA9Cl+LmwKoyR2OLgcnmw4cD+0yFMtZiph2+NTZUF7EdzYtrGsDEsyb04vsdCtAuGlcVaQJUNTG9WK5ggQKkcJfyrdB58lz44IS2g0oAHuPnqR3Pw5WJl9aLXYDwkCNIODPcIUssgJbQXEOX14GiRW6BBhHz5wDPV+/IuJGfmUT5Fd5TmVZ676Dl3JzsiNkSlpWwQ3Osg1lCn1lFCifz7WC4zDz6fK593Bgwr/Hfa4wb0F3hIAgOAIEXCuCecVxrubGY4V80gy3l0VFRZdKIDOsDqxXBfVVnkCWsf5JvJibQ1VNZKLolrnzc4psYxtLGMNBmU0edwwcYkyQtQzFZkzoe2QNgoOZNG53cfzM+bDfjdwXKxJk8aPeA8comHJm4JaymJETN/k8nv7NFcQnMkFzDPLZhh6WnxRLoEzjW4anNHolOTwyhnuZaKAnA4QATWwlK9/ag7mpRrrEQG12vIynHd9FOJ+WCbpn7X5IkV3qY4tEKVOCmDgm8U2Sf2JwwsBZtlpf2vhyzKEPDXCsDW5iAsW/xt2H6KZoplD5X8u2jgW9vfmqxuSk+8VPzcLh9TKxqH5T8QOEKW6xUFQ0aYvVV5/VmWBti1+qfVFgAhMPeGwUwoHAyi3GGFRoyAzepxtEaUs3769wH9Wa6v4FT/PT/piLqWEClHXFdxFJXEhjitYcwLUl1IXJNk9+qLAC9L79YXFhvBgTxQbZ63B9I8YZXHSaaQ5zUaP48Ra0YGhz1eoqHV+lpxna8PkvwOgHtHBg0kt+RoL9KbHOnSaQfHtxJe5YShjz/Z11tAvyzHD41oAYZ+QuLVbsuDg8DF37DlP1hUVCWTkmwCaa2lDWjmot9W8XdXXRzZJvDTV1rYagyONKxm6LAjff11qCnC20JVXMzWPJ5cuby2GF2wue42fGdV/IoEMnz9DdHUT5RWyMlsM3TS6obg5uqaObxjhyrY5/wtOgny0yFfYqiatJdyMBKHP3LwgYQ2HAZJZQYMRnhqArm04Y9INiB6QQcKoOHocDFy6T2DBCE0dcr05bVW2OyF1MJSDYRvyOQZJYviAA+HM/T+TWMsxVhDROL7qTSOLfkmMvDfo5NqwWB3gnC91CkPZ8IWtw11NcrZVjBg1f1UQ3R7NI60eCOKGE8xgFNS1B3KmaANVPkr//Fus5VMA/tyRhkcZdmLhLMehnGn6tyCjuUGItTF8VVLCOlgBfDx+YkV2KLArOIgBtsjiCeWwRZpAAcRUZgYtpCBuCetruWd+LQKgNnjvou/FP2ZkqzW1T10KxhQ0UUTtJ6bv/XZlZoifHMWWOFWgTBe5gxzdpnkXAycC5bsISHHyimIKFNa24D+JBXZlTTVjyU/meugn39EksEhi0zC333KY2PJWUVfzedLWhQ8mW0QXv1ldAZllDIM/mHCbuqVdb5krXWV1Pi4kkYQkgrpfJPjpPGHbdz0rf8dWvaEw/flRvfnmDqebH22oaH1QVFd0W/qtFSTzBSwBx3U18wOQESRuVrzf4o1cTBvzDY4hsfYwAlMzdESSYkLCEJSxhCUtYwhKWsITdDPb/D+d8y6SEZ48AAAAASUVORK5CYII=';

	private static function logo_data_uri() {
		return 'data:image/png;base64,' . self::LOGO_PNG_BASE64;
	}

	/** @var array<string,string> module directory name => class name, in load order */
	/**
	 * Order here drives both activation sequence and admin-menu position
	 * (register()/activate() run in this order, and each module's own
	 * add_submenu_page() call happens in that same sequence) — so this
	 * list is grouped into rough categories for the sidebar, not just
	 * build order. The one hard constraint: vuln-scanner must stay ahead
	 * of auto-update, since "update what was flagged" mode reads the
	 * scanner's last result. Everything else here is free to reorder.
	 */
	private static $modules = array(
		// Overview — read/audit views over the shared events table.
		// event-log first: it owns that table.
		'event-log'       => 'WPOpsec_Module_Event_Log',
		'geo-map'         => 'WPOpsec_Module_Geo_Map',
		'activity-log'    => 'WPOpsec_Module_Activity_Log',
		'bot-log'         => 'WPOpsec_Module_Bot_Log',

		// Perimeter — blocks by IP/identity before WordPress finishes loading.
		'ip-blocklist'    => 'WPOpsec_Module_IP_Blocklist',
		'whitelist'       => 'WPOpsec_Module_Whitelist',
		'geo-blocker'     => 'WPOpsec_Module_Geo_Blocker',
		// geo-login right after geo-blocker: it reuses that module's
		// compiled country dataset and class, so must load after it.
		'geo-login'       => 'WPOpsec_Module_Geo_Login',
		'rate-limiter'    => 'WPOpsec_Module_Rate_Limiter',

		// Request inspection — looks at what a request is doing, not just who it's from.
		'query-guard'     => 'WPOpsec_Module_Query_Guard',
		'login-guard'     => 'WPOpsec_Module_Login_Guard',

		// Integrity & detection — is anything already wrong.
		'file-integrity'  => 'WPOpsec_Module_File_Integrity',
		'malware-scanner' => 'WPOpsec_Module_Malware_Scanner',
		'vuln-scanner'    => 'WPOpsec_Module_Vuln_Scanner',
		'user-watchdog'   => 'WPOpsec_Module_User_Watchdog',

		// Hardening — reduces what an attacker can do after getting in.
		'headers'         => 'WPOpsec_Module_Headers',
		'user-enum'       => 'WPOpsec_Module_User_Enum',
		'hardening'       => 'WPOpsec_Module_Hardening',

		// Ops — keeping the above current and knowing when it fires.
		'auto-update'     => 'WPOpsec_Module_Auto_Update',
		'alerts'          => 'WPOpsec_Module_Alerts',
		'ip-sharing'      => 'WPOpsec_Module_IP_Sharing',
		'scan-all'        => 'WPOpsec_Module_Scan_All',
		'config-io'       => 'WPOpsec_Module_Config_IO',
	);

	/**
	 * Shared WP_Filesystem instance for the local, plugin-managed file
	 * writes every module does (compiled datasets, mu-plugin sync, the
	 * local blocklist cache) — never user uploads or anything reachable
	 * from a public request. Only for admin-post/cron/activation-context
	 * callers: it requires wp-admin/includes/file.php and, on the rare
	 * host without direct filesystem access, can need credentials — both
	 * fine for those contexts, but wrong for the early-gate check.php
	 * files, which run pre-bootstrap on every front-end request and stay
	 * on raw fopen()/fread() for that reason (documented at each site).
	 */
	public static function filesystem() {
		global $wp_filesystem;
		if ( ! $wp_filesystem ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			WP_Filesystem();
		}
		return $wp_filesystem;
	}

	public static function init() {
		self::ensure_mu_loader_current();

		// The mu-plugin WordPress loaded this request is whatever was on disk
		// when the request started. Right after a plugin update that's the
		// *previous* version, so helpers the new module code calls may not be
		// defined yet — the copy above only fixes the next request. Load the
		// fresh file now if anything is missing. require_once dedups by path,
		// so this is a no-op once the current file is already loaded.
		if ( ! function_exists( 'wpopsec_log_event' ) && file_exists( WPOPSEC_MU_DEST ) ) {
			require_once WPOPSEC_MU_DEST;
		}

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ), 5 );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_assets' ) );
		WPOpsec_Menu_Router::register();

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'register' ) ) {
				call_user_func( array( $class, 'register' ) );
			}
		}
	}

	public static function activate() {
		self::copy_mu_loader();

		// Guarantee the shared helpers (wpopsec_local_blocklist_add() etc.)
		// are defined in *this* process before module activate() hooks run.
		// Normal bootstrap loads this file as an actual mu-plugin before
		// plugins_loaded fires, but on a fresh/re-activation the file may
		// not have existed yet when that happened this same request —
		// require_once dedups by path, so this is a no-op when it's already
		// loaded and a real load when it wasn't.
		require_once WPOPSEC_MU_DEST;

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'activate' ) ) {
				call_user_func( array( $class, 'activate' ) );
			}
		}
	}

	public static function deactivate() {
		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'deactivate' ) ) {
				call_user_func( array( $class, 'deactivate' ) );
			}
		}

		self::remove_mu_loader();
	}

	public static function admin_menu() {
		add_menu_page(
			'ShieldCore Security',
			'ShieldCore Security',
			'manage_options',
			'wp-opsec',
			array( __CLASS__, 'render_dashboard' ),
			'dashicons-shield'
		);
	}

	/**
	 * Every Opsec admin page's hook suffix contains "wp-opsec" — the
	 * top-level page is "toplevel_page_wp-opsec", every cluster submenu
	 * (registered by WPOpsec_Menu_Router against the "wp-opsec" parent) is
	 * "wp-opsec_page_wp-opsec-<cluster>". Enqueued unconditionally across
	 * all of them, one bundle covering every module's admin UI, rather than
	 * detecting which of the tabs within a cluster page is active: none of
	 * this CSS varies by request, and the combined size is trivial.
	 *
	 * Must run at admin_enqueue_scripts — by the time a page's own render
	 * callback runs, wp-admin has already printed admin_print_styles() into
	 * <head>, so a style enqueued any later would silently never appear.
	 */
	public static function enqueue_assets( $hook ) {
		if ( false === strpos( (string) $hook, 'wp-opsec' ) ) {
			return;
		}
		wp_enqueue_style( 'wpopsec-admin', WPOPSEC_PLUGIN_URL . 'assets/admin.css', array(), WPOPSEC_VERSION );
		wp_enqueue_style( 'wpopsec-dashboard', WPOPSEC_PLUGIN_URL . 'assets/dashboard.css', array( 'wpopsec-admin' ), WPOPSEC_VERSION );
		wp_enqueue_style( 'wpopsec-geo-map', WPOPSEC_PLUGIN_URL . 'assets/geo-map.css', array(), WPOPSEC_VERSION );
	}

	/**
	 * Module status cards. Each entry describes one module's current posture:
	 * `level` drives the colour (good / warn / bad / off) and is what the
	 * overall score is computed from.
	 */
	private static function status_cards() {
		$ip_mode  = get_option( 'wpopsec_ip_blocklist_mode', 'log' );
		$qg_mode  = get_option( 'wpopsec_query_guard_mode', 'log' );
		$lg_on    = (bool) get_option( 'wpopsec_login_guard_enabled', true );
		$headers  = class_exists( 'WPOpsec_Module_Headers' ) ? WPOpsec_Module_Headers::build() : array();
		$ue_on    = (bool) get_option( 'wpopsec_user_enum_block_author_scan', true );
		$fi_base  = (int) get_option( 'wpopsec_integrity_baseline_at', 0 );
		$vuln     = get_option( 'wpopsec_vuln_last_result', array() );
		$au_plug  = get_option( 'wpopsec_auto_update_plugins', 'flagged' );
		$uw_alert = count( (array) get_option( 'wpopsec_user_watchdog_alerts', array() ) );
		$hidden   = count( (array) ( get_option( 'wpopsec_hardening_hidden_result', array() )['hidden'] ?? array() ) );
		$editor   = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;

		$vuln_findings = count( (array) ( $vuln['findings'] ?? array() ) );
		$integrity     = self::integrity_issue_count();

		$mal_last     = get_option( 'wpopsec_malware_last_result', array() );
		$mal_findings = count( (array) ( $mal_last['findings'] ?? array() ) );
		$geo_stats    = get_option( 'wpopsec_geo_stats', array() );
		$geo_selected = count( (array) get_option( 'wpopsec_geo_countries', array() ) );
		$geo_enforce  = get_option( 'wpopsec_geo_enforce_mode', 'log' );
		$gl_selected  = count( (array) get_option( 'wpopsec_geo_login_countries', array() ) );
		$gl_enforce   = get_option( 'wpopsec_geo_login_enforce_mode', 'log' );
		$al_count     = count( (array) get_option( 'wpopsec_activity_categories', array( 'content', 'plugins_themes', 'settings' ) ) );
		$rl_on        = (bool) get_option( 'wpopsec_ratelimit_enabled', true );
		$rl_mode      = get_option( 'wpopsec_ratelimit_mode', 'log' );

		return array(
			array(
				'key'   => 'ip-blocklist',
				'title' => 'IP Blocklist',
				'icon'  => 'shield-alt',
				'state' => 'block' === $ip_mode ? 'Blocking' : 'Log only',
				'level' => 'block' === $ip_mode ? 'good' : 'warn',
				'note'  => sprintf(
					'%s ranges loaded',
					number_format_i18n( (int) ( get_option( 'wpopsec_ip_blocklist_stats', array() )['count_merged'] ?? 0 ) )
				),
			),
			array(
				'key'   => 'query-guard',
				'title' => 'Query Guard',
				'icon'  => 'filter',
				'state' => 'block' === $qg_mode ? 'Blocking' : 'Log only',
				'level' => 'block' === $qg_mode ? 'good' : 'warn',
				'note'  => get_option( 'wpopsec_query_guard_scan_post', true ) ? 'GET + POST scanning' : 'GET only',
			),
			array(
				'key'   => 'login-guard',
				'title' => 'Login Guard',
				'icon'  => 'lock',
				'state' => $lg_on ? 'Enabled' : 'Disabled',
				'level' => $lg_on ? 'good' : 'bad',
				'note'  => sprintf(
					'%d fails / %d min',
					(int) get_option( 'wpopsec_login_guard_max_fails', 8 ),
					(int) get_option( 'wpopsec_login_guard_window_min', 15 )
				),
			),
			array(
				'key'   => 'headers',
				'title' => 'Security Headers',
				'icon'  => 'shield',
				'state' => $headers ? sprintf( '%d active', count( $headers ) ) : 'None',
				'level' => $headers ? 'good' : 'bad',
				'note'  => isset( $headers['Strict-Transport-Security'] ) ? 'HSTS on' : 'HSTS off',
			),
			array(
				'key'   => 'user-enum',
				'title' => 'User Enumeration',
				'icon'  => 'hidden',
				'state' => $ue_on ? 'Protected' : 'Open',
				'level' => $ue_on ? 'good' : 'bad',
				'note'  => get_option( 'wpopsec_user_enum_block_rest_users', true ) ? 'REST users locked' : 'REST users public',
			),
			array(
				'key'   => 'file-integrity',
				'title' => 'File Integrity',
				'icon'  => 'media-code',
				'state' => $integrity > 0 ? sprintf( '%d change(s)', $integrity ) : ( $fi_base ? 'Clean' : 'No baseline' ),
				'level' => $integrity > 0 ? 'bad' : ( $fi_base ? 'good' : 'warn' ),
				'note'  => $fi_base ? sprintf( 'baseline %s', date_i18n( 'M j', $fi_base ) ) : 'take a baseline',
			),
			array(
				'key'   => 'vuln-scanner',
				'title' => 'Vulnerability Scan',
				'icon'  => 'search',
				'state' => $vuln ? ( $vuln_findings ? sprintf( '%d flagged', $vuln_findings ) : 'Clean' ) : 'Not run',
				'level' => $vuln ? ( $vuln_findings ? 'bad' : 'good' ) : 'warn',
				'note'  => $vuln ? sprintf( '%d components checked', (int) ( $vuln['scanned_count'] ?? 0 ) ) : 'never scanned',
			),
			array(
				'key'   => 'auto-update',
				'title' => 'Auto Updates',
				'icon'  => 'update',
				'state' => 'off' === $au_plug ? 'Plugins off' : ( 'all' === $au_plug ? 'All plugins' : 'Flagged only' ),
				'level' => 'off' === $au_plug ? 'warn' : 'good',
				'note'  => sprintf( 'core: %s', get_option( 'wpopsec_auto_update_core', 'minor' ) ),
			),
			array(
				'key'   => 'user-watchdog',
				'title' => 'User Watchdog',
				'icon'  => 'admin-users',
				'state' => $uw_alert ? sprintf( '%d alert(s)', $uw_alert ) : 'Clear',
				'level' => $uw_alert ? 'bad' : 'good',
				'note'  => sprintf(
					'%d privileged account(s)',
					count( (array) get_option( 'wpopsec_user_watchdog_snapshot', array() ) )
				),
			),
			array(
				'key'   => 'hardening',
				'title' => 'Hardening',
				'icon'  => 'admin-tools',
				'state' => $hidden ? sprintf( '%d hidden plugin(s)', $hidden ) : ( $editor ? 'Editor off' : 'Editor on' ),
				'level' => $hidden ? 'bad' : ( $editor ? 'good' : 'warn' ),
				'note'  => class_exists( 'WPOpsec_Module_Hardening' ) && WPOpsec_Module_Hardening::uploads_guard_active()
					? 'uploads guarded'
					: 'uploads unguarded',
			),
			array(
				'key'   => 'alerts',
				'title' => 'Alerts',
				'icon'  => 'testimonial',
				'state' => self::alerts_ready_count() ? sprintf( '%d channel(s)', self::alerts_ready_count() ) : ( self::alerts_any_enabled() ? 'Needs setup' : 'Disabled' ),
				'level' => self::alerts_ready_count() ? 'good' : 'warn',
				'note'  => self::alerts_channel_summary(),
			),
			array(
				'key'   => 'ip-sharing',
				'title' => 'IP Sharing',
				'icon'  => 'shield-alt',
				'state' => get_option( 'wpopsec_unwantedip_enabled', false ) ? 'Enabled' : 'Disabled',
				'level' => get_option( 'wpopsec_unwantedip_enabled', false )
					? ( get_option( 'wpopsec_unwantedip_api_key', '' ) ? 'good' : 'warn' )
					: 'warn',
				'note'  => 'blocked IPs only',
			),
			array(
				'key'   => 'malware-scanner',
				'title' => 'Malware Scanner',
				'icon'  => 'warning',
				'state' => $mal_last ? ( $mal_findings ? sprintf( '%d finding(s)', $mal_findings ) : 'Clean' ) : 'Not run',
				'level' => $mal_last ? ( $mal_findings ? 'bad' : 'good' ) : 'warn',
				'note'  => $mal_last ? sprintf( '%d file(s) scanned', (int) ( $mal_last['scanned_count'] ?? 0 ) ) : 'never scanned',
			),
			array(
				'key'   => 'geo-blocker',
				'title' => 'Geo Blocker',
				'icon'  => 'admin-site-alt3',
				'state' => $geo_selected ? sprintf( '%d country(ies)', $geo_selected ) : 'Not configured',
				'level' => $geo_selected ? ( 'block' === $geo_enforce ? 'good' : 'warn' ) : 'warn',
				'note'  => $geo_stats ? sprintf( '%s ranges indexed', number_format_i18n( (int) ( $geo_stats['count'] ?? 0 ) ) ) : 'no dataset yet',
			),
			array(
				'key'   => 'geo-login',
				'title' => 'Geo Login',
				'icon'  => 'lock',
				'state' => $gl_selected ? sprintf( '%d country(ies)', $gl_selected ) : 'Not configured',
				'level' => $gl_selected ? ( 'block' === $gl_enforce ? 'good' : 'warn' ) : 'warn',
				'note'  => 'wp-login.php only',
			),
			array(
				'key'   => 'activity-log',
				'title' => 'Activity Log',
				'icon'  => 'edit-page',
				'state' => $al_count ? sprintf( '%d categor(ies)', $al_count ) : 'Disabled',
				'level' => $al_count ? 'good' : 'warn',
				'note'  => 'posts, plugins, themes, settings',
			),
			array(
				'key'   => 'rate-limiter',
				'title' => 'Rate Limiter',
				'icon'  => 'clock',
				'state' => ! $rl_on ? 'Disabled' : ( 'block' === $rl_mode ? 'Blocking' : 'Log only' ),
				'level' => ! $rl_on ? 'warn' : ( 'block' === $rl_mode ? 'good' : 'warn' ),
				'note'  => sprintf( '%s req/min per IP', number_format_i18n( (int) get_option( 'wpopsec_ratelimit_per_minute', 300 ) ) ),
			),
			array(
				'key'   => 'geo-map',
				'title' => 'Event Map',
				'icon'  => 'admin-site-alt3',
				'state' => class_exists( 'WPOpsec_Module_Geo_Map' ) ? sprintf( '%d countries · 7d', count( WPOpsec_Module_Geo_Map::counts_by_country( 7 ) ) ) : 'Unavailable',
				'level' => 'good', // read-only visualization, nothing to misconfigure
				'note'  => 'blocked + logged events, by country',
			),
		);
	}

	private static function alerts_tg_ready() {
		return get_option( 'wpopsec_telegram_enabled', false )
			&& get_option( 'wpopsec_telegram_bot_token', '' )
			&& get_option( 'wpopsec_telegram_chat_id', '' );
	}

	private static function alerts_email_ready() {
		return get_option( 'wpopsec_email_enabled', false )
			&& ( get_option( 'wpopsec_email_address', '' ) || get_option( 'admin_email' ) );
	}

	private static function alerts_ready_count() {
		return ( self::alerts_tg_ready() ? 1 : 0 ) + ( self::alerts_email_ready() ? 1 : 0 );
	}

	private static function alerts_any_enabled() {
		return get_option( 'wpopsec_telegram_enabled', false ) || get_option( 'wpopsec_email_enabled', false );
	}

	private static function alerts_channel_summary() {
		$on = array_filter(
			array(
				get_option( 'wpopsec_telegram_enabled', false ) ? 'Telegram' : null,
				get_option( 'wpopsec_email_enabled', false ) ? 'Email' : null,
			)
		);
		return $on ? implode( ' + ', $on ) : 'no channel configured';
	}

	private static function integrity_issue_count() {
		$last = get_option( 'wpopsec_integrity_last_result', array() );
		if ( empty( $last ) ) {
			return 0;
		}
		return count( (array) ( $last['core']['modified'] ?? array() ) )
			+ count( (array) ( $last['core']['missing'] ?? array() ) )
			+ count( (array) ( $last['diff']['added'] ?? array() ) )
			+ count( (array) ( $last['diff']['modified'] ?? array() ) );
	}

	public static function render_dashboard() {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		// $table is always wpopsec_events_table() (built from $wpdb->prefix, no user input) -- identifiers can't be
		// bound via $wpdb->prepare() placeholders anyway. This is a dashboard summary read over the whole events
		// table (up to a 7-day window or a flat LIMIT 12), not a per-request lookup worth an object-cache group for.
		$table     = wpopsec_events_table();
		$has_table = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;

		$by_module = array();
		$recent    = array();
		$daily     = array();
		$totals    = array( 'blocked' => 0, 'logged' => 0, 'noted' => 0 );
		$worst     = 0;
		$sev_module = array();

		if ( $has_table ) {
			$worst = (int) $wpdb->get_var(
				"SELECT MAX(severity) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)"
			);

			$sev_rows = $wpdb->get_results(
				"SELECT module, MAX(severity) s FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY) GROUP BY module",
				ARRAY_A
			) ?: array();
			foreach ( $sev_rows as $r ) {
				$sev_module[ $r['module'] ] = (int) $r['s'];
			}
		}

		if ( $has_table ) {
			$counts = $wpdb->get_results(
				"SELECT module, action, COUNT(*) c
				 FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
				 GROUP BY module, action",
				ARRAY_A
			) ?: array();

			foreach ( $counts as $row ) {
				$by_module[ $row['module'] ][ $row['action'] ] = (int) $row['c'];
				if ( isset( $totals[ $row['action'] ] ) ) {
					$totals[ $row['action'] ] += (int) $row['c'];
				}
			}

			$rows = $wpdb->get_results(
				"SELECT DATE(created_at) d, COUNT(*) c
				 FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
				 GROUP BY DATE(created_at)",
				ARRAY_A
			) ?: array();

			$seen = array();
			foreach ( $rows as $r ) {
				$seen[ $r['d'] ] = (int) $r['c'];
			}
			for ( $i = 6; $i >= 0; $i-- ) {
				$day             = gmdate( 'Y-m-d', strtotime( "-{$i} days" ) );
				$daily[ $day ]   = $seen[ $day ] ?? 0;
			}

			$recent = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 12" ) ?: array();
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$cards = self::status_cards();

		// Simple posture score: every module contributes equally, partial
		// credit for "on but not enforcing". It's a nudge toward the weak
		// spots, not a claim of measured risk.
		$score = 0;
		foreach ( $cards as $c ) {
			$score += ( 'good' === $c['level'] ) ? 1 : ( ( 'warn' === $c['level'] ) ? 0.5 : 0 );
		}
		$score   = (int) round( ( $score / max( 1, count( $cards ) ) ) * 100 );
		$s_level = $score >= 85 ? 'good' : ( $score >= 60 ? 'warn' : 'bad' );
		$s_label = $score >= 85 ? 'Strong' : ( $score >= 60 ? 'Needs attention' : 'Weak' );

		// Core protection: the baseline modules a site should turn on
		// regardless of what it is — as opposed to optional integrations
		// (Telegram, IP Sharing, Geo Blocker/Login, Activity Log) that many
		// sites will legitimately never want, and User Watchdog/Event Map
		// whose "not good" states are live alerts or read-only views, not
		// unfinished setup. Keeping this list separate from the general
		// attention line means the headline banner only ever nags about
		// things actually worth finishing, not things worth ignoring.
		$core_keys = array(
			'ip-blocklist',
			'query-guard',
			'login-guard',
			'headers',
			'user-enum',
			'file-integrity',
			'malware-scanner',
			'vuln-scanner',
			'rate-limiter',
			'hardening',
		);

		$core_gaps = array_values(
			array_filter(
				$cards,
				function ( $c ) use ( $core_keys ) {
					return in_array( $c['key'], $core_keys, true ) && 'good' !== $c['level'];
				}
			)
		);

		$attention = array_values(
			array_filter(
				$cards,
				function ( $c ) use ( $core_keys ) {
					return 'good' !== $c['level'] && ! in_array( $c['key'], $core_keys, true );
				}
			)
		);

		// CSS is enqueued externally via enqueue_assets() (admin_enqueue_scripts),
		// not printed here — by the time this callback runs, wp-admin's <head>
		// has already been sent.
		?>
		<div class="wrap wpopsec wpopsec-dash">
			<h1 class="wpopsec-title">
				<img src="<?php echo esc_attr( self::logo_data_uri() ); ?>" alt="" width="30" height="30">
				ShieldCore Security
			</h1>

			<div class="wpopsec-hero">
				<div class="wpopsec-score wpopsec-score--<?php echo esc_attr( $s_level ); ?>">
					<div class="wpopsec-score__ring" style="--pct:<?php echo esc_attr( $score ); ?>">
						<div class="wpopsec-score__num"><?php echo esc_html( $score ); ?><span>%</span></div>
					</div>
					<div class="wpopsec-score__label"><?php echo esc_html( $s_label ); ?></div>
				</div>

				<div class="wpopsec-hero__stats">
					<div class="wpopsec-stat wpopsec-stat--bad">
						<span class="dashicons dashicons-dismiss"></span>
						<div>
							<strong><?php echo esc_html( number_format_i18n( $totals['blocked'] ) ); ?></strong>
							<span>blocked · 7 days</span>
						</div>
					</div>
					<div class="wpopsec-stat wpopsec-stat--warn">
						<span class="dashicons dashicons-visibility"></span>
						<div>
							<strong><?php echo esc_html( number_format_i18n( $totals['logged'] ) ); ?></strong>
							<span>would block (log only)</span>
						</div>
					</div>
					<?php list( $w_label, $w_color ) = wpopsec_severity_meta( $worst ); ?>
					<div class="wpopsec-stat">
						<span class="dashicons dashicons-warning" style="color:<?php echo esc_attr( $worst ? $w_color : '#646970' ); ?>"></span>
						<div>
							<strong><?php echo $worst ? esc_html( $worst ) . '<span style="font-size:13px;font-weight:400;color:#646970">/20</span>' : '—'; ?></strong>
							<span>worst severity<?php echo $worst ? esc_html( ' · ' . $w_label ) : ''; ?></span>
						</div>
					</div>

					<?php if ( $daily ) : ?>
						<div class="wpopsec-spark">
							<?php
							$max = max( 1, max( $daily ) );
							foreach ( $daily as $day => $n ) :
								$h = max( 3, (int) round( ( $n / $max ) * 46 ) );
								?>
								<span class="wpopsec-spark__bar"
									style="height:<?php echo esc_attr( $h ); ?>px"
									title="<?php echo esc_attr( sprintf( '%s — %d event(s)', date_i18n( 'D j M', strtotime( $day ) ), $n ) ); ?>"></span>
							<?php endforeach; ?>
						</div>
					<?php endif; ?>
				</div>
			</div>

			<?php if ( $core_gaps ) : ?>
				<div class="wpopsec-protect wpopsec-protect--bad">
					<div class="wpopsec-protect__head">
						<span class="dashicons dashicons-shield-alt"></span>
						<div>
							<strong>You're not fully protected yet</strong>
							<span><?php echo esc_html( sprintf( '%d of %d core module(s) still need attention.', count( $core_gaps ), count( $core_keys ) ) ); ?></span>
						</div>
					</div>
					<ul class="wpopsec-protect__list">
						<?php foreach ( $core_gaps as $g ) : ?>
							<li>
								<a href="<?php echo esc_url( WPOpsec_Menu_Router::url( $g['key'] ) ); ?>">
									<span class="dashicons dashicons-arrow-right-alt2"></span>
									<strong><?php echo esc_html( $g['title'] ); ?></strong>
									<em><?php echo esc_html( $g['state'] ); ?></em>
								</a>
							</li>
						<?php endforeach; ?>
					</ul>
				</div>
			<?php else : ?>
				<div class="wpopsec-protect wpopsec-protect--good">
					<div class="wpopsec-protect__head">
						<span class="dashicons dashicons-yes-alt"></span>
						<div>
							<strong>Core protection fully configured</strong>
							<span>Every baseline module is on and enforcing.</span>
						</div>
					</div>
				</div>
			<?php endif; ?>

			<?php if ( $attention ) : ?>
				<div class="wpopsec-attention">
					<span class="dashicons dashicons-info"></span>
					<div>
						<strong>Optional, not yet set up:</strong>
						<?php
						$links = array();
						foreach ( $attention as $a ) {
							$links[] = sprintf(
								'<a href="%s">%s <em>(%s)</em></a>',
								esc_url( WPOpsec_Menu_Router::url( $a['key'] ) ),
								esc_html( $a['title'] ),
								esc_html( strtolower( $a['state'] ) )
							);
						}
						echo wp_kses_post( implode( ' · ', $links ) );
						?>
					</div>
				</div>
			<?php endif; ?>

			<h2 class="wpopsec-h2">Modules</h2>
			<div class="wpopsec-grid">
				<?php foreach ( $cards as $card ) : ?>
					<?php
					$blocked = $by_module[ $card['key'] ]['blocked'] ?? 0;
					$logged  = $by_module[ $card['key'] ]['logged'] ?? 0;
					$noted   = $by_module[ $card['key'] ]['noted'] ?? 0;
					$total   = $blocked + $logged + $noted;
					?>
					<a class="wpopsec-card wpopsec-card--<?php echo esc_attr( $card['level'] ); ?>"
						href="<?php echo esc_url( WPOpsec_Menu_Router::url( $card['key'] ) ); ?>">
						<div class="wpopsec-card__top">
							<span class="wpopsec-card__icon dashicons dashicons-<?php echo esc_attr( $card['icon'] ); ?>"></span>
							<span class="wpopsec-card__title"><?php echo esc_html( $card['title'] ); ?></span>
							<?php if ( ! empty( $sev_module[ $card['key'] ] ) ) : ?>
								<?php list( $cs_label, $cs_color ) = wpopsec_severity_meta( $sev_module[ $card['key'] ] ); ?>
								<span class="wpopsec-sevdot"
									style="background:<?php echo esc_attr( $cs_color ); ?>"
									title="<?php echo esc_attr( sprintf( 'Worst severity in 7 days: %d (%s)', $sev_module[ $card['key'] ], $cs_label ) ); ?>"><?php echo esc_html( $sev_module[ $card['key'] ] ); ?></span>
							<?php endif; ?>
						</div>
						<div class="wpopsec-pill"><?php echo esc_html( $card['state'] ); ?></div>
						<div class="wpopsec-card__note"><?php echo esc_html( $card['note'] ); ?></div>
						<div class="wpopsec-card__foot">
							<?php if ( $total ) : ?>
								<?php if ( $blocked ) : ?>
									<span class="wpopsec-chip wpopsec-chip--bad"><?php echo esc_html( number_format_i18n( $blocked ) ); ?> blocked</span>
								<?php endif; ?>
								<?php if ( $logged ) : ?>
									<span class="wpopsec-chip wpopsec-chip--warn"><?php echo esc_html( number_format_i18n( $logged ) ); ?> logged</span>
								<?php endif; ?>
								<?php if ( $noted && ! $blocked && ! $logged ) : ?>
									<span class="wpopsec-chip"><?php echo esc_html( number_format_i18n( $noted ) ); ?> events</span>
								<?php endif; ?>
							<?php else : ?>
								<span class="wpopsec-chip wpopsec-chip--quiet">no activity</span>
							<?php endif; ?>
						</div>
					</a>
				<?php endforeach; ?>
			</div>

			<h2 class="wpopsec-h2">
				Recent activity
				<a class="wpopsec-h2__link" href="<?php echo esc_url( WPOpsec_Menu_Router::url( 'event-log' ) ); ?>">View full log →</a>
			</h2>

			<?php if ( empty( $recent ) ) : ?>
				<div class="wpopsec-empty">
					<span class="dashicons dashicons-yes-alt"></span>
					<p>No events recorded yet. Modules in log-only mode will record here as traffic arrives.</p>
				</div>
			<?php else : ?>
				<table class="wpopsec-table">
					<thead>
						<tr>
							<th style="width:56px">Sev</th>
							<th style="width:130px">Time</th>
							<th style="width:120px">Module</th>
							<th style="width:170px">Event</th>
							<th style="width:90px">Action</th>
							<th style="width:120px">IP</th>
							<th>Detail</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $recent as $row ) : ?>
						<?php list( $rs_label, $rs_color ) = wpopsec_severity_meta( $row->severity ); ?>
						<tr>
							<td>
								<span class="wpopsec-sevdot" style="background:<?php echo esc_attr( $rs_color ); ?>"
									title="<?php echo esc_attr( $rs_label ); ?>"><?php echo esc_html( (int) $row->severity ); ?></span>
							</td>
							<td class="wpopsec-nowrap"><?php echo esc_html( mysql2date( 'M j, H:i', $row->created_at ) ); ?></td>
							<td><span class="wpopsec-mod"><?php echo esc_html( $row->module ); ?></span></td>
							<td><code><?php echo esc_html( $row->event ); ?></code></td>
							<td>
								<?php if ( 'blocked' === $row->action ) : ?>
									<span class="wpopsec-chip wpopsec-chip--bad">blocked</span>
								<?php elseif ( 'logged' === $row->action ) : ?>
									<span class="wpopsec-chip wpopsec-chip--warn">logged</span>
								<?php else : ?>
									<span class="wpopsec-chip wpopsec-chip--quiet">noted</span>
								<?php endif; ?>
							</td>
							<td class="wpopsec-nowrap"><code><?php echo esc_html( $row->ip ); ?></code></td>
							<td class="wpopsec-detail"><?php echo esc_html( $row->detail ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}


	private static function load_module( $module ) {
		$file = WPOPSEC_PLUGIN_DIR . "includes/modules/{$module}/module.php";
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}

	private static function copy_mu_loader() {
		if ( ! file_exists( WPMU_PLUGIN_DIR ) ) {
			wp_mkdir_p( WPMU_PLUGIN_DIR );
		}
		copy( WPOPSEC_MU_SOURCE, WPOPSEC_MU_DEST );

		// Every other rewritten data file in this plugin does this; the
		// mu-loader itself — by far the most consequential one, since it
		// defines every shared function — never did. Without it, a request
		// handled by a worker process that already had the old bytecode
		// opcache-compiled can keep serving stale function definitions
		// until that cache entry's own revalidation timer fires, which is
		// a real window for a fatal "undefined function" on a real request
		// if this file changed (new function added) during it — confirmed
		// live, not hypothetical: hit a real admin session's own
		// admin-ajax request during this exact deploy window.
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( WPOPSEC_MU_DEST, true );
		}
	}

	private static function remove_mu_loader() {
		if ( file_exists( WPOPSEC_MU_DEST ) ) {
			self::filesystem()->delete( WPOPSEC_MU_DEST );
		}
	}

	/**
	 * Keep the deployed mu-plugin file in sync with the version shipped in
	 * this plugin (e.g. after a plugin update), without requiring reactivation.
	 */
	private static function ensure_mu_loader_current() {
		if ( ! file_exists( WPOPSEC_MU_DEST )
			|| md5_file( WPOPSEC_MU_DEST ) !== md5_file( WPOPSEC_MU_SOURCE ) ) {
			self::copy_mu_loader();
		}
	}
}
