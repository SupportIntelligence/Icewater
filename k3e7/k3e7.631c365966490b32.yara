import "hash"

rule k3e7_631c365966490b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.631c365966490b32"
     cluster="k3e7.631c365966490b32"
     cluster_size="212 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit corrupt corruptfile"
     md5_hashes="['834ed61576f0507ac56a517cd581032f', '25d1c73486a0de13da1c703aced19728', '8bf3876329986c30df3bc9698409ffa4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "bd200fe0cb55b40e4c02f3c22dfff560"
}

