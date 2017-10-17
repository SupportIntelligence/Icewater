import "hash"

rule m3ef_099d6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ef.099d6a49c0000b12"
     cluster="m3ef.099d6a49c0000b12"
     cluster_size="2856 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="linkury unwanted malicious"
     md5_hashes="['0daacec81ced5ac35f8782cf3e99bd9f', '2d4b49139d180dbd8a3cf4490c264442', '18fd253c81cbbffe692326c62513301d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(17408,1024) == "9ec20f329e2dfd0aba23877984fc6b69"
}

