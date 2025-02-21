"""MIT License

Copyright (c) 2025 EAST TIMOR GHOST SECURITY (Mr.Y)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

import base64, hashlib, os

code = "IiIiTUlUIExpY2Vuc2UKCkNvcHlyaWdodCAoYykgMjAyNSBFQVNUIFRJTU9SIEdIT1NUIFNFQ1VSSVRZIChNci5ZKQoKUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGEgY29weQpvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZSAiU29mdHdhcmUiKSwgdG8gZGVhbAppbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzCnRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCwgZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwKY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdCBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzCmZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGUgZm9sbG93aW5nIGNvbmRpdGlvbnM6CgpUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZCBpbiBhbGwKY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS4KClRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCAiQVMgSVMiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTIE9SCklNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZLApGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUKQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSwgREFNQUdFUyBPUiBPVEhFUgpMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLApPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEUgVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRQpTT0ZUV0FSRS4iIiIKCgppbXBvcnQgYWlvaHR0cAppbXBvcnQgYXN5bmNpbwppbXBvcnQgdXJsbGliLnBhcnNlCmltcG9ydCBsb2dnaW5nCmltcG9ydCBqc29uCmltcG9ydCByZQppbXBvcnQgdGltZQppbXBvcnQgc2lnbmFsCmltcG9ydCBzeXMKCiMgU2V0dXAgbG9nZ2luZwpsb2dnaW5nLmJhc2ljQ29uZmlnKGZpbGVuYW1lPSd2dWxuZXJhYmlsaXR5X3NjYW4ubG9nJywgbGV2ZWw9bG9nZ2luZy5JTkZPLCBmb3JtYXQ9JyUoYXNjdGltZSlzIC0gJShsZXZlbG5hbWUpcyAtICUobWVzc2FnZSlzJykKCmNsYXNzIFZ1bG5lcmFiaWxpdHlTY2FubmVyOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIHRhcmdldF91cmwpOgogICAgICAgIHNlbGYudGFyZ2V0X3VybCA9IHRhcmdldF91cmwKICAgICAgICBzZWxmLnJlc3VsdHMgPSBbXQoKICAgIGFzeW5jIGRlZiBmZXRjaChzZWxmLCBzZXNzaW9uLCB1cmwpOgogICAgICAgICIiIkZldGNoIHRoZSBVUkwgYW5kIHJldHVybiB0aGUgcmVzcG9uc2UgdGV4dCBhbmQgc3RhdHVzLiIiIgogICAgICAgIHRyeToKICAgICAgICAgICAgYXN5bmMgd2l0aCBzZXNzaW9uLmdldCh1cmwpIGFzIHJlc3BvbnNlOgogICAgICAgICAgICAgICAgcmV0dXJuIGF3YWl0IHJlc3BvbnNlLnRleHQoKSwgcmVzcG9uc2Uuc3RhdHVzCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBsb2dnaW5nLmVycm9yKGYiRXJyb3IgZmV0Y2hpbmcge3VybH06IHtlfSIpCiAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCgogICAgYXN5bmMgZGVmIGNoZWNrX3JjZShzZWxmLCBwYXlsb2FkKToKICAgICAgICAiIiJDaGVjayBmb3IgUmVtb3RlIENvZGUgRXhlY3V0aW9uIHZ1bG5lcmFiaWxpdGllcy4iIiIKICAgICAgICB0ZXN0X3VybCA9IGYie3NlbGYudGFyZ2V0X3VybH0/Y21kPXt1cmxsaWIucGFyc2UucXVvdGUocGF5bG9hZCl9IgogICAgICAgIGFzeW5jIHdpdGggYWlvaHR0cC5DbGllbnRTZXNzaW9uKCkgYXMgc2Vzc2lvbjoKICAgICAgICAgICAgcmVzcG9uc2VfdGV4dCwgc3RhdHVzID0gYXdhaXQgc2VsZi5mZXRjaChzZXNzaW9uLCB0ZXN0X3VybCkKICAgICAgICAgICAgaWYgc3RhdHVzID09IDIwMDoKICAgICAgICAgICAgICAgICMgSGV1cmlzdGljIGRldGVjdGlvbiBmb3IgUkNFCiAgICAgICAgICAgICAgICBpZiAiZXhwZWN0ZWRfb3V0cHV0IiBpbiByZXNwb25zZV90ZXh0OiAgIyBSZXBsYWNlIHdpdGggZXhwZWN0ZWQgb3V0cHV0CiAgICAgICAgICAgICAgICAgICAgc2VsZi5yZXN1bHRzLmFwcGVuZChmIlshXSBQb3RlbnRpYWwgUkNFIHZ1bG5lcmFiaWxpdHkgZm91bmQgd2l0aCBwYXlsb2FkOiB7cGF5bG9hZH0iKQogICAgICAgICAgICAgICAgZWxpZiByZS5zZWFyY2gocidlcnJvcnxleGNlcHRpb258ZmFpbGVkfGNvbW1hbmQgbm90IGZvdW5kJywgcmVzcG9uc2VfdGV4dCwgcmUuSUdOT1JFQ0FTRSk6CiAgICAgICAgICAgICAgICAgICAgc2VsZi5yZXN1bHRzLmFwcGVuZChmIlshXSBQb3NzaWJsZSBSQ0UgdnVsbmVyYWJpbGl0eSBpbmRpY2F0ZWQgYnkgZXJyb3IgbWVzc2FnZSB3aXRoIHBheWxvYWQ6IHtwYXlsb2FkfSIpCgogICAgYXN5bmMgZGVmIGNoZWNrX2xmaShzZWxmLCBwYXlsb2FkKToKICAgICAgICAiIiJDaGVjayBmb3IgTG9jYWwgRmlsZSBJbmNsdXNpb24gdnVsbmVyYWJpbGl0aWVzLiIiIgogICAgICAgIHRlc3RfdXJsID0gZiJ7c2VsZi50YXJnZXRfdXJsfT9maWxlPXt1cmxsaWIucGFyc2UucXVvdGUocGF5bG9hZCl9IgogICAgICAgIGFzeW5jIHdpdGggYWlvaHR0cC5DbGllbnRTZXNzaW9uKCkgYXMgc2Vzc2lvbjoKICAgICAgICAgICAgcmVzcG9uc2VfdGV4dCwgc3RhdHVzID0gYXdhaXQgc2VsZi5mZXRjaChzZXNzaW9uLCB0ZXN0X3VybCkKICAgICAgICAgICAgaWYgc3RhdHVzID09IDIwMDoKICAgICAgICAgICAgICAgICMgSGV1cmlzdGljIGRldGVjdGlvbiBmb3IgTEZJCiAgICAgICAgICAgICAgICBpZiAiZXhwZWN0ZWRfY29udGVudCIgaW4gcmVzcG9uc2VfdGV4dDogICMgUmVwbGFjZSB3aXRoIGV4cGVjdGVkIGNvbnRlbnQKICAgICAgICAgICAgICAgICAgICBzZWxmLnJlc3VsdHMuYXBwZW5kKGYiWyFdIFBvdGVudGlhbCBMRkkgdnVsbmVyYWJpbGl0eSBmb3VuZCB3aXRoIHBheWxvYWQ6IHtwYXlsb2FkfSIpCiAgICAgICAgICAgICAgICBlbGlmIHJlLnNlYXJjaChyJ2Vycm9yfGV4Y2VwdGlvbnxmYWlsZWR8bm8gc3VjaCBmaWxlIG9yIGRpcmVjdG9yeScsIHJlc3BvbnNlX3RleHQsIHJlLklHTk9SRUNBU0UpOgogICAgICAgICAgICAgICAgICAgIHNlbGYucmVzdWx0cy5hcHBlbmQoZiJbIV0gUG9zc2libGUgTEZJIHZ1bG5lcmFiaWxpdHkgaW5kaWNhdGVkIGJ5IGVycm9yIG1lc3NhZ2Ugd2l0aCBwYXlsb2FkOiB7cGF5bG9hZH0iKQoKICAgIGFzeW5jIGRlZiBjaGVja19kaXJlY3RvcnlfdHJhdmVyc2FsKHNlbGYsIHBheWxvYWQpOgogICAgICAgICIiIkNoZWNrIGZvciBEaXJlY3RvcnkgVHJhdmVyc2FsIHZ1bG5lcmFiaWxpdGllcy4iIiIKICAgICAgICB0ZXN0X3VybCA9IGYie3NlbGYudGFyZ2V0X3VybH0/ZmlsZT17dXJsbGliLnBhcnNlLnF1b3RlKHBheWxvYWQpfSIKICAgICAgICBhc3luYyB3aXRoIGFpb2h0dHAuQ2xpZW50U2Vzc2lvbigpIGFzIHNlc3Npb246CiAgICAgICAgICAgIHJlc3BvbnNlX3RleHQsIHN0YXR1cyA9IGF3YWl0IHNlbGYuZmV0Y2goc2Vzc2lvbiwgdGVzdF91cmwpCiAgICAgICAgICAgIGlmIHN0YXR1cyA9PSAyMDA6CiAgICAgICAgICAgICAgICAjIEhldXJpc3RpYyBkZXRlY3Rpb24gZm9yIERpcmVjdG9yeSBUcmF2ZXJzYWwKICAgICAgICAgICAgICAgIGlmICJleHBlY3RlZF9jb250ZW50IiBpbiByZXNwb25zZV90ZXh0OiAgIyBSZXBsYWNlIHdpdGggZXhwZWN0ZWQgY29udGVudAogICAgICAgICAgICAgICAgICAgIHNlbGYucmVzdWx0cy5hcHBlbmQoZiJbIV0gUG90ZW50aWFsIERpcmVjdG9yeSBUcmF2ZXJzYWwgdnVsbmVyYWJpbGl0eSBmb3VuZCB3aXRoIHBheWxvYWQ6IHtwYXlsb2FkfSIpCiAgICAgICAgICAgICAgICBlbGlmIHJlLnNlYXJjaChyJ2Vycm9yfGV4Y2VwdGlvbnxmYWlsZWR8bm8gc3VjaCBmaWxlIG9yIGRpcmVjdG9yeScsIHJlc3BvbnNlX3RleHQsIHJlLklHTk9SRUNBU0UpOgogICAgICAgICAgICAgICAgICAgIHNlbGYucmVzdWx0cy5hcHBlbmQoZiJbIV0gUG9zc2libGUgRGlyZWN0b3J5IFRyYXZlcnNhbCB2dWxuZXJhYmlsaXR5IGluZGljYXRlZCBieSBlcnJvciBtZXNzYWdlIHdpdGggcGF5bG9hZDoge3BheWxvYWR9IikKCiAgICBhc3luYyBkZWYgY2hlY2tfc2Vzc2lvbl9oaWphY2tpbmcoc2VsZik6CiAgICAgICAgIiIiQ2hlY2sgZm9yIFNlc3Npb24gSGlqYWNraW5nIHZ1bG5lcmFiaWxpdGllcy4iIiIKICAgICAgICBpZiAic2Vzc2lvbl9pZCIgaW4gc2VsZi50YXJnZXRfdXJsOgogICAgICAgICAgICBzZWxmLnJlc3VsdHMuYXBwZW5kKCJbIV0gUG90ZW50aWFsIFNlc3Npb24gSGlqYWNraW5nIHZ1bG5lcmFiaWxpdHkgZm91bmQ6IFNlc3Npb24gSUQgaW4gVVJMIikKCiAgICBhc3luYyBkZWYgY2hlY2tfaW5zZWN1cmVfZGF0YV9zdG9yYWdlKHNlbGYpOgogICAgICAgICIiIkNoZWNrIGZvciBJbnNlY3VyZSBEYXRhIFN0b3JhZ2UgdnVsbmVyYWJpbGl0aWVzLiIiIgogICAgICAgIGlmICJwYXNzd29yZCIgaW4gc2VsZi50YXJnZXRfdXJsIG9yICJ0b2tlbiIgaW4gc2VsZi50YXJnZXRfdXJsOgogICAgICAgICAgICBzZWxmLnJlc3VsdHMuYXBwZW5kKCJbIV0gUG90ZW50aWFsIEluc2VjdXJlIERhdGEgU3RvcmFnZSB2dWxuZXJhYmlsaXR5IGZvdW5kOiBTZW5zaXRpdmUgZGF0YSBpbiBVUkwiKQoKICAgIGFzeW5jIGRlZiBjaGVja194eGUoc2VsZiwgcGF5bG9hZCk6CiAgICAgICAgIiIiQ2hlY2sgZm9yIFhNTCBFeHRlcm5hbCBFbnRpdHkgdnVsbmVyYWJpbGl0aWVzLiIiIgogICAgICAgIGhlYWRlcnMgPSB7J0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94bWwnfQogICAgICAgIGRhdGEgPSBmIiIiPD94bWwgdmVyc2lvbj0iMS4wIj8+CiAgICAgICAgPCFET0NUWVBFIGZvbyBbCiAgICAgICAgICAgIDwhRU5USVRZIHh4ZSBTWVNURU0gIntwYXlsb2FkfSI+CiAgICAgICAgXT4KICAgICAgICA8Zm9vPiZ4eGU7PC9mb28+IiIiCiAgICAgICAgYXN5bmMgd2l0aCBhaW9odHRwLkNsaWVudFNlc3Npb24oKSBhcyBzZXNzaW9uOgogICAgICAgICAgICBhc3luYyB3aXRoIHNlc3Npb24ucG9zdChzZWxmLnRhcmdldF91cmwsIGRhdGE9ZGF0YSwgaGVhZGVycz1oZWFkZXJzKSBhcyByZXNwb25zZToKICAgICAgICAgICAgICAgIHJlc3BvbnNlX3RleHQgPSBhd2FpdCByZXNwb25zZS50ZXh0KCkKICAgICAgICAgICAgICAgIGlmIHJlc3BvbnNlLnN0YXR1cyA9PSAyMDA6CiAgICAgICAgICAgICAgICAgICAgIyBIZXVyaXN0aWMgZGV0ZWN0aW9uIGZvciBYWEUKICAgICAgICAgICAgICAgICAgICBpZiAiZXhwZWN0ZWRfY29udGVudCIgaW4gcmVzcG9uc2VfdGV4dDogICMgUmVwbGFjZSB3aXRoIGV4cGVjdGVkIGNvbnRlbnQKICAgICAgICAgICAgICAgICAgICAgICAgc2VsZi5yZXN1bHRzLmFwcGVuZChmIlshXSBQb3RlbnRpYWwgWFhFIHZ1bG5lcmFiaWxpdHkgZm91bmQgd2l0aCBwYXlsb2FkOiB7cGF5bG9hZH0iKQogICAgICAgICAgICAgICAgICAgIGVsaWYgcmUuc2VhcmNoKHInZXJyb3J8ZXhjZXB0aW9ufGZhaWxlZCcsIHJlc3BvbnNlX3RleHQsIHJlLklHTk9SRUNBU0UpOgogICAgICAgICAgICAgICAgICAgICAgICBzZWxmLnJlc3VsdHMuYXBwZW5kKGYiWyFdIFBvc3NpYmxlIFhYRSB2dWxuZXJhYmlsaXR5IGluZGljYXRlZCBieSBlcnJvciBtZXNzYWdlIHdpdGggcGF5bG9hZDoge3BheWxvYWR9IikKCiAgICBhc3luYyBkZWYgY2hlY2tfc3NyZihzZWxmLCBwYXlsb2FkKToKICAgICAgICAiIiJDaGVjayBmb3IgU2VydmVyLVNpZGUgUmVxdWVzdCBGb3JnZXJ5IHZ1bG5lcmFiaWxpdGllcy4iIiIKICAgICAgICB0ZXN0X3VybCA9IGYie3NlbGYudGFyZ2V0X3VybH0/dXJsPXt1cmxsaWIucGFyc2UucXVvdGUocGF5bG9hZCl9IgogICAgICAgIGFzeW5jIHdpdGggYWlvaHR0cC5DbGllbnRTZXNzaW9uKCkgYXMgc2Vzc2lvbjoKICAgICAgICAgICAgcmVzcG9uc2VfdGV4dCwgc3RhdHVzID0gYXdhaXQgc2VsZi5mZXRjaChzZXNzaW9uLCB0ZXN0X3VybCkKICAgICAgICAgICAgaWYgc3RhdHVzID09IDIwMDoKICAgICAgICAgICAgICAgICMgSGV1cmlzdGljIGRldGVjdGlvbiBmb3IgU1NSRgogICAgICAgICAgICAgICAgaWYgImV4cGVjdGVkX2NvbnRlbnQiIGluIHJlc3BvbnNlX3RleHQ6ICAjIFJlcGxhY2Ugd2l0aCBleHBlY3RlZCBjb250ZW50CiAgICAgICAgICAgICAgICAgICAgc2VsZi5yZXN1bHRzLmFwcGVuZChmIlshXSBQb3RlbnRpYWwgU1NSRiB2dWxuZXJhYmlsaXR5IGZvdW5kIHdpdGggcGF5bG9hZDoge3BheWxvYWR9IikKICAgICAgICAgICAgICAgIGVsaWYgcmUuc2VhcmNoKHInZXJyb3J8ZXhjZXB0aW9ufGZhaWxlZCcsIHJlc3BvbnNlX3RleHQsIHJlLklHTk9SRUNBU0UpOgogICAgICAgICAgICAgICAgICAgIHNlbGYucmVzdWx0cy5hcHBlbmQoZiJbIV0gUG9zc2libGUgU1NSRiB2dWxuZXJhYmlsaXR5IGluZGljYXRlZCBieSBlcnJvciBtZXNzYWdlIHdpdGggcGF5bG9hZDoge3BheWxvYWR9IikKCiAgICBhc3luYyBkZWYgY2hlY2tfeHNzaShzZWxmKToKICAgICAgICAiIiJDaGVjayBmb3IgQ3Jvc3MtU2l0ZSBTY3JpcHQgSW5jbHVzaW9uIHZ1bG5lcmFiaWxpdGllcy4iIiIKICAgICAgICB0ZXN0X3VybCA9IGYie3NlbGYudGFyZ2V0X3VybH0/c2NyaXB0PWV4YW1wbGUuanMiICAjIEFkanVzdCB0aGUgcGFyYW1ldGVyIGFzIG5lZWRlZAogICAgICAgIGFzeW5jIHdpdGggYWlvaHR0cC5DbGllbnRTZXNzaW9uKCkgYXMgc2Vzc2lvbjoKICAgICAgICAgICAgcmVzcG9uc2VfdGV4dCwgc3RhdHVzID0gYXdhaXQgc2VsZi5mZXRjaChzZXNzaW9uLCB0ZXN0X3VybCkKICAgICAgICAgICAgaWYgc3RhdHVzID09IDIwMDoKICAgICAgICAgICAgICAgICMgSGV1cmlzdGljIGRldGVjdGlvbiBmb3IgWFNTSQogICAgICAgICAgICAgICAgaWYgInNlbnNpdGl2ZV9kYXRhIiBpbiByZXNwb25zZV90ZXh0OiAgIyBSZXBsYWNlIHdpdGggZXhwZWN0ZWQgY29udGVudAogICAgICAgICAgICAgICAgICAgIHNlbGYucmVzdWx0cy5hcHBlbmQoIlshXSBQb3RlbnRpYWwgWFNTSSB2dWxuZXJhYmlsaXR5IGZvdW5kOiBTZW5zaXRpdmUgZGF0YSBpbmNsdWRlZCBpbiBzY3JpcHQuIikKCiAgICBhc3luYyBkZWYgcnVuX2NoZWNrcyhzZWxmLCBjaGVja190eXBlLCBwYXlsb2Fkcyk6CiAgICAgICAgIiIiUnVuIHRoZSBzcGVjaWZpZWQgY2hlY2tzIGJhc2VkIG9uIHRoZSB0eXBlIGFuZCBwYXlsb2Fkcy4iIiIKICAgICAgICB0YXNrcyA9IFtdCiAgICAgICAgZm9yIHBheWxvYWQgaW4gcGF5bG9hZHM6CiAgICAgICAgICAgIGlmIGNoZWNrX3R5cGUgPT0gJ1JDRSc6CiAgICAgICAgICAgICAgICB0YXNrcy5hcHBlbmQoc2VsZi5jaGVja19yY2UocGF5bG9hZCkpCiAgICAgICAgICAgIGVsaWYgY2hlY2tfdHlwZSA9PSAnTEZJJzoKICAgICAgICAgICAgICAgIHRhc2tzLmFwcGVuZChzZWxmLmNoZWNrX2xmaShwYXlsb2FkKSkKICAgICAgICAgICAgZWxpZiBjaGVja190eXBlID09ICdEaXJlY3RvcnkgVHJhdmVyc2FsJzoKICAgICAgICAgICAgICAgIHRhc2tzLmFwcGVuZChzZWxmLmNoZWNrX2RpcmVjdG9yeV90cmF2ZXJzYWwocGF5bG9hZCkpCiAgICAgICAgICAgIGVsaWYgY2hlY2tfdHlwZSA9PSAnWFhFJzoKICAgICAgICAgICAgICAgIHRhc2tzLmFwcGVuZChzZWxmLmNoZWNrX3h4ZShwYXlsb2FkKSkKICAgICAgICAgICAgZWxpZiBjaGVja190eXBlID09ICdTU1JGJzoKICAgICAgICAgICAgICAgIHRhc2tzLmFwcGVuZChzZWxmLmNoZWNrX3NzcmYocGF5bG9hZCkpCiAgICAgICAgYXdhaXQgYXN5bmNpby5nYXRoZXIoKnRhc2tzKQoKICAgIGRlZiBzYXZlX3Jlc3VsdHMoc2VsZik6CiAgICAgICAgIiIiU2F2ZSB0aGUgcmVzdWx0cyB0byBhIEpTT04gZmlsZS4iIiIKICAgICAgICB3aXRoIG9wZW4oJ3NjYW5fcmVzdWx0cy5qc29uJywgJ3cnKSBhcyBmOgogICAgICAgICAgICBqc29uLmR1bXAoc2VsZi5yZXN1bHRzLCBmLCBpbmRlbnQ9NCkKCmRlZiBsb2FkX3BheWxvYWRzKGZpbGVfcGF0aCk6CiAgICAiIiJMb2FkIHBheWxvYWRzIGZyb20gYSBmaWxlLiIiIgogICAgdHJ5OgogICAgICAgIHdpdGggb3BlbihmaWxlX3BhdGgsICdyJykgYXMgZmlsZToKICAgICAgICAgICAgcmV0dXJuIFtsaW5lLnN0cmlwKCkgZm9yIGxpbmUgaW4gZmlsZSBpZiBsaW5lLnN0cmlwKCldCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcHJpbnQoZiJbRVJST1JdIEZpbGUge2ZpbGVfcGF0aH0gbm90IGZvdW5kLiIpCiAgICAgICAgcmV0dXJuIFtdCgpkZWYgcHJpbnRfd2l0aF9kZWxheSh0ZXh0LCBkZWxheT0wLjAzKToKICAgIGZvciBjaGFyIGluIHRleHQ6CiAgICAgICAgcHJpbnQoY2hhciwgZW5kPScnLCBmbHVzaD1UcnVlKQogICAgICAgIHRpbWUuc2xlZXAoZGVsYXkpCiAgICBwcmludCgpICAjIE5ldyBsaW5lIGFmdGVyIHRoZSB0ZXh0CgojIERpc3BsYXkgYmFubmVyIHdpdGggYW5pbWF0aW9uCmJhbm5lciA9ICIiIgpcMDMzWzE7MzNt4paI4paI4paI4paI4paI4paI4paI4pWXIOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilojilojilojilojilojilZfilojilojilojilojilojilojilojilojilZcgICAg4paI4paI4paI4paI4paI4paI4paI4paI4pWX4paI4paI4pWX4paI4paI4paI4pWXICAg4paI4paI4paI4pWXIOKWiOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilojilojilojilojilZcgICAgICDilojilojilojilojilojilojilZcg4paI4paI4pWXICDilojilojilZcg4paI4paI4paI4paI4paI4paI4pWXIOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVl+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVl+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKVl+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilojilojilojilojilZcKXDAzM1sxOzMzbeKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVneKWiOKWiOKVlOKVkOKVkOKWiOKWiOKVl+KWiOKWiOKVlOKVkOKVkOKVkOKVkOKVneKVmuKVkOKVkOKWiOKWiOKVlOKVkOKVkOKVnSAgICDilZrilZDilZDilojilojilZTilZDilZDilZ3ilojilojilZHilojilojilojilojilZcg4paI4paI4paI4paI4pWR4paI4paI4pWU4pWQ4pWQ4pWQ4paI4paI4pWX4paI4paI4pWU4pWQ4pWQ4paI4paI4pWXICAgIOKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVnSDilojilojilZEgIOKWiOKWiOKVkeKWiOKWiOKVlOKVkOKVkOKVkOKWiOKWiOKVl+KWiOKWiOKVlOKVkOKVkOKVkOKVkOKVneKVmuKVkOKVkOKWiOKWiOKVlOKVkOKVkOKVneKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVneKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVneKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVnQpcMDMzWzE7Mzdt4paI4paI4paI4paI4paI4pWXICDilojilojilojilojilojilojilojilZHilojilojilojilojilojilojilojilZcgICDilojilojilZEgICAgICAgICAg4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWU4paI4paI4paI4paI4pWU4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4paI4paI4paI4paI4pWU4pWdICAgIOKWiOKWiOKVkSAg4paI4paI4paI4pWX4paI4paI4paI4paI4paI4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4paI4paI4paI4paI4paI4pWXICAg4paI4paI4pWRICAg4paI4paI4paI4paI4paI4paI4paI4pWX4paI4paI4paI4paI4paI4pWXICDilojilojilZEgICAgIApcMDMzWzE7Mzdt4paI4paI4pWU4pWQ4pWQ4pWdICDilojilojilZTilZDilZDilojilojilZHilZrilZDilZDilZDilZDilojilojilZEgICDilojilojilZEgICAgICAgICAg4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWR4pWa4paI4paI4pWU4pWd4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWU4pWQ4pWQ4paI4paI4pWXICAgIOKWiOKWiOKVkSAgIOKWiOKWiOKVkeKWiOKWiOKVlOKVkOKVkOKWiOKWiOKVkeKWiOKWiOKVkSAgIOKWiOKWiOKVkeKVmuKVkOKVkOKVkOKVkOKWiOKWiOKVkSAgIOKWiOKWiOKVkSAgIOKVmuKVkOKVkOKVkOKVkOKWiOKWiOKVkeKWiOKWiOKVlOKVkOKVkOKVnSAg4paI4paI4pWRICAgICAKXDAzM1sxOzMxbeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVl+KWiOKWiOKVkSAg4paI4paI4pWR4paI4paI4paI4paI4paI4paI4paI4pWRICAg4paI4paI4pWRICAgICAgICAgIOKWiOKWiOKVkSAgIOKWiOKWiOKVkeKWiOKWiOKVkSDilZrilZDilZ0g4paI4paI4pWR4pWa4paI4paI4paI4paI4paI4paI4pWU4pWd4paI4paI4pWRICDilojilojilZEgICAg4pWa4paI4paI4paI4paI4paI4paI4pWU4pWd4paI4paI4pWRICDilojilojilZHilZrilojilojilojilojilojilojilZTilZ3ilojilojilojilojilojilojilojilZEgICDilojilojilZEgICDilojilojilojilojilojilojilojilZHilojilojilojilojilojilojilojilZfilZrilojilojilojilojilojilojilZcKXDAzM1sxOzMxbeKVmuKVkOKVkOKVkOKVkOKVkOKVkOKVneKVmuKVkOKVnSAg4pWa4pWQ4pWd4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWdICAg4pWa4pWQ4pWdICAgICAgICAgIOKVmuKVkOKVnSAgIOKVmuKVkOKVneKVmuKVkOKVnSAgICAg4pWa4pWQ4pWdIOKVmuKVkOKVkOKVkOKVkOKVkOKVnSDilZrilZDilZ0gIOKVmuKVkOKVnSAgICAg4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWdIOKVmuKVkOKVnSAg4pWa4pWQ4pWdIOKVmuKVkOKVkOKVkOKVkOKVkOKVnSDilZrilZDilZDilZDilZDilZDilZDilZ0gICDilZrilZDilZ0gICDilZrilZDilZDilZDilZDilZDilZDilZ3ilZrilZDilZDilZDilZDilZDilZDilZ0g4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWdClwwMzNbMG0KIiIiCgojIEF1dGhvciBpbmZvCmF1dGhvcl9pbmZvID0gIkNvZGUgYnkgRUFTVCBUSU1PUiBHSE9TVCBTRUNVUklUWSAoTXIuWSkgdmVyc2lvbjogMS4yIgoKIyBDYWxjdWxhdGUgdGhlIHBvc2l0aW9uIHRvIGNlbnRlciB0aGUgYXV0aG9yIGluZm8KYmFubmVyX2xpbmVzID0gYmFubmVyLnN0cmlwKCkuc3BsaXQoJ1xuJykKbWF4X2xlbmd0aCA9IG1heChsZW4obGluZSkgZm9yIGxpbmUgaW4gYmFubmVyX2xpbmVzKQpjZW50ZXJlZF9hdXRob3JfaW5mbyA9IGF1dGhvcl9pbmZvLmNlbnRlcihtYXhfbGVuZ3RoKQoKIyBDb21iaW5lIGJhbm5lciBhbmQgYXV0aG9yIGluZm8KZnVsbF9iYW5uZXIgPSAiXG4iLmpvaW4oYmFubmVyX2xpbmVzKSArICJcbiIgKyBjZW50ZXJlZF9hdXRob3JfaW5mbyArICJcbiIKCiMgUHJpbnQgYmFubmVyIGFuZCBhdXRob3IgaW5mbyB3aXRoIGFuaW1hdGlvbgpwcmludF93aXRoX2RlbGF5KGZ1bGxfYmFubmVyKQoKIyBGdW5jdGlvbiB0byBoYW5kbGUgQ3RybCtDCmRlZiBzaWduYWxfaGFuZGxlcihzaWcsIGZyYW1lKToKICAgIHByaW50KCJcbiIsIGVuZD0iIikKICAgIHByaW50X3dpdGhfZGVsYXkoIlRIQU5LIFlPVSBGT1IgVVNJTkcgVEhFIFRPT0xTIiwgZGVsYXk9MC4wNSkKICAgIHN5cy5leGl0KDApCgojIFJlZ2lzdGVyIHRoZSBzaWduYWwgaGFuZGxlcgpzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIHNpZ25hbF9oYW5kbGVyKQogICAgICAgIAphc3luYyBkZWYgbWFpbigpOgogICAgcHJpbnQoIj09PT09PT09PT09PT1TRUxFQ1QgWU9VUiBPUFRJT05TPT09PT09PT09PT09PT09PSIpCiAgICBwcmludCgiWzFdIENoZWNrIGZvciBSQ0UgdnVsbmVyYWJpbGl0aWVzIikKICAgIHByaW50KCJbMl0gQ2hlY2sgZm9yIExGSSB2dWxuZXJhYmlsaXRpZXMiKQogICAgcHJpbnQoIlszXSBDaGVjayBmb3IgRGlyZWN0b3J5IFRyYXZlcnNhbCB2dWxuZXJhYmlsaXRpZXMiKQogICAgcHJpbnQoIls0XSBDaGVjayBmb3IgU2Vzc2lvbiBIaWphY2tpbmcgdnVsbmVyYWJpbGl0aWVzIikKICAgIHByaW50KCJbNV0gQ2hlY2sgZm9yIEluc2VjdXJlIERhdGEgU3RvcmFnZSB2dWxuZXJhYmlsaXRpZXMiKQogICAgcHJpbnQoIls2XSBDaGVjayBmb3IgWE1MIEV4dGVybmFsIEVudGl0eSAoWFhFKSB2dWxuZXJhYmlsaXRpZXMiKQogICAgcHJpbnQoIls3XSBDaGVjayBmb3IgU2VydmVyLVNpZGUgUmVxdWVzdCBGb3JnZXJ5IChTU1JGKSB2dWxuZXJhYmlsaXRpZXMiKQogICAgcHJpbnQoIls4XSBDaGVjayBmb3IgQ3Jvc3MtU2l0ZSBTY3JpcHQgSW5jbHVzaW9uIChYU1NJKSB2dWxuZXJhYmlsaXRpZXMiKQoKICAgIGNob2ljZSA9IGlucHV0KCJFbnRlciB5b3VyIGNob2ljZSAoMS04KTogIikKICAgIHRhcmdldF91cmwgPSBpbnB1dCgiRW50ZXIgdGhlIHRhcmdldCBVUkw6ICIpCiAgICBzY2FubmVyID0gVnVsbmVyYWJpbGl0eVNjYW5uZXIodGFyZ2V0X3VybCkKCiAgICBpZiBjaG9pY2UgPT0gJzEnOgogICAgICAgIHJjZV9wYXlsb2Fkc19maWxlID0gaW5wdXQoIkVudGVyIHRoZSBwYXRoIHRvIHRoZSBSQ0UgcGF5bG9hZCBmaWxlOiAiKQogICAgICAgIHJjZV9wYXlsb2FkcyA9IGxvYWRfcGF5bG9hZHMocmNlX3BheWxvYWRzX2ZpbGUpCiAgICAgICAgYXdhaXQgc2Nhbm5lci5ydW5fY2hlY2tzKCdSQ0UnLCByY2VfcGF5bG9hZHMpCiAgICBlbGlmIGNob2ljZSA9PSAnMic6CiAgICAgICAgbGZpX3BheWxvYWRzX2ZpbGUgPSBpbnB1dCgiRW50ZXIgdGhlIHBhdGggdG8gdGhlIExGSSBwYXlsb2FkIGZpbGU6ICIpCiAgICAgICAgbGZpX3BheWxvYWRzID0gbG9hZF9wYXlsb2FkcyhsZmlfcGF5bG9hZHNfZmlsZSkKICAgICAgICBhd2FpdCBzY2FubmVyLnJ1bl9jaGVja3MoJ0xGSScsIGxmaV9wYXlsb2FkcykKICAgIGVsaWYgY2hvaWNlID09ICczJzoKICAgICAgICBkaXJfdHJhdmVyc2FsX3BheWxvYWRzX2ZpbGUgPSBpbnB1dCgiRW50ZXIgdGhlIHBhdGggdG8gdGhlIERpcmVjdG9yeSBUcmF2ZXJzYWwgcGF5bG9hZCBmaWxlOiAiKQogICAgICAgIGRpcl90cmF2ZXJzYWxfcGF5bG9hZHMgPSBsb2FkX3BheWxvYWRzKGRpcl90cmF2ZXJzYWxfcGF5bG9hZHNfZmlsZSkKICAgICAgICBhd2FpdCBzY2FubmVyLnJ1bl9jaGVja3MoJ0RpcmVjdG9yeSBUcmF2ZXJzYWwnLCBkaXJfdHJhdmVyc2FsX3BheWxvYWRzKQogICAgZWxpZiBjaG9pY2UgPT0gJzQnOgogICAgICAgIGF3YWl0IHNjYW5uZXIuY2hlY2tfc2Vzc2lvbl9oaWphY2tpbmcoKQogICAgZWxpZiBjaG9pY2UgPT0gJzUnOgogICAgICAgIGF3YWl0IHNjYW5uZXIuY2hlY2tfaW5zZWN1cmVfZGF0YV9zdG9yYWdlKCkKICAgIGVsaWYgY2hvaWNlID09ICc2JzoKICAgICAgICB4eGVfcGF5bG9hZHNfZmlsZSA9IGlucHV0KCJFbnRlciB0aGUgcGF0aCB0byB0aGUgWFhFIHBheWxvYWQgZmlsZTogIikKICAgICAgICB4eGVfcGF5bG9hZHMgPSBsb2FkX3BheWxvYWRzKHh4ZV9wYXlsb2Fkc19maWxlKQogICAgICAgIGF3YWl0IHNjYW5uZXIucnVuX2NoZWNrcygnWFhFJywgeHhlX3BheWxvYWRzKQogICAgZWxpZiBjaG9pY2UgPT0gJzcnOgogICAgICAgIHNzcmZfcGF5bG9hZHNfZmlsZSA9IGlucHV0KCJFbnRlciB0aGUgcGF0aCB0byB0aGUgU1NSRiBwYXlsb2FkIGZpbGU6ICIpCiAgICAgICAgc3NyZl9wYXlsb2FkcyA9IGxvYWRfcGF5bG9hZHMoc3NyZl9wYXlsb2Fkc19maWxlKQogICAgICAgIGF3YWl0IHNjYW5uZXIucnVuX2NoZWNrcygnU1NSRicsIHNzcmZfcGF5bG9hZHMpCiAgICBlbGlmIGNob2ljZSA9PSAnOCc6CiAgICAgICAgYXdhaXQgc2Nhbm5lci5jaGVja194c3NpKCkKICAgIGVsc2U6CiAgICAgICAgcHJpbnQoIltFUlJPUl0gSW52YWxpZCBjaG9pY2UuIEV4aXRpbmcuIikKICAgICAgICByZXR1cm4KCiAgICAjIFNhdmUgcmVzdWx0cyB0byBhIEpTT04gZmlsZQogICAgc2Nhbm5lci5zYXZlX3Jlc3VsdHMoKQogICAgcHJpbnQoIltJTkZPXSBTY2FuIGNvbXBsZXRlZC4gUmVzdWx0cyBzYXZlZCB0byBzY2FuX3Jlc3VsdHMuanNvbi4iKQoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIGFzeW5jaW8ucnVuKG1haW4oKSkK"
decoded = base64.b64decode(code).decode()

current_hash = hashlib.sha256(decoded.encode()).hexdigest()

expected_hash = "90aa2309d3fe00247a28d118f6d40cf489e3ede4ce87b3f5909323ed86050267"

if current_hash != expected_hash:
    print("Warning: Keta modifika beik...")
    os.remove(__file__) 
    exit()

exec(decoded)
