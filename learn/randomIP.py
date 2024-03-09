import random


class Solution:
    def validIPAddress(self, queryIP: str) -> str:
        if queryIP.find(".") != -1:
            # IPv4
            last = -1
            for i in range(4):
                cur = (len(queryIP) if i == 3 else queryIP.find(".", last + 1))
                if cur == -1:
                    return "Neither"
                if not 1 <= cur - last - 1 <= 3:
                    return "Neither"

                addr = 0
                for j in range(last + 1, cur):
                    if not queryIP[j].isdigit():
                        return "Neither"
                    addr = addr * 10 + int(queryIP[j])

                if addr > 255:
                    return "Neither"
                if addr > 0 and queryIP[last + 1] == "0":
                    return "Neither"
                if addr == 0 and cur - last - 1 > 1:
                    return "Neither"

                last = cur

            return "IPv4"
        else:
            # IPv6
            last = -1
            for i in range(8):
                cur = (len(queryIP) if i == 7 else queryIP.find(":", last + 1))
                if cur == -1:
                    return "Neither"
                if not 1 <= cur - last - 1 <= 4:
                    return "Neither"

                for j in range(last + 1, cur):
                    if not queryIP[j].isdigit() and not ("a" <= queryIP[j].lower() <= "f"):
                        return "Neither"

                last = cur

            return "IPv6"


def IPV4():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def IPV6():
    return ":".join(format(random.randint(0, 65535), 'x') for _ in range(8))


def RANDOM_NAME(suffix: str = '', randomLen: int = 8):
    charlist = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM_'
    ans = ''
    ans += suffix
    for _ in range(randomLen):
        ans += charlist[random.randint(0, len(charlist) - 1)]
    return ans


if __name__ == '__main__':
    # so = Solution()
    # for _ in range(100):
    #     ip6 = IPV4()
    #     print('>' * 64)
    #     print(ip6)
    #     print(so.validIPAddress(ip6))
    #     print('<' * 64)

    print(RANDOM_NAME(suffix='MQTT_', randomLen=9))
