import "hash"

rule m3ed_133995b79aab1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.133995b79aab1912"
     cluster="m3ed.133995b79aab1912"
     cluster_size="72 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="browsefox unwanted bplug"
     md5_hashes="['1fe2e1ab176dc1ea141e7e1b9efac0bd', '22546bf8a0b47a7a4e21337532d0e491', 'd1b6ffaf6a45a64c597edf283122e3cd']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(153088,1024) == "0b0c967f7773c99320bea013fed416b3"
}

