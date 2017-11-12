import "hash"

rule k400_211e94d9c2200912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.211e94d9c2200912"
     cluster="k400.211e94d9c2200912"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="tdss zusy pondfull"
     md5_hashes="['a82e27384be930e2e77756bc0095d5e0', 'c3b62b3d30806d35af4d06188c564d2d', '98195282db4b82a39e7c43717634a436']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "3025b8da6f6636d25a7916a09dd7c178"
}

