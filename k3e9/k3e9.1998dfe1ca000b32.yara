import "hash"

rule k3e9_1998dfe1ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1998dfe1ca000b32"
     cluster="k3e9.1998dfe1ca000b32"
     cluster_size="24929"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre jqvu tiny"
     md5_hashes="['0005eaf6ac838d2542b883779fac53ce','0012024e7d4e591148a678db9996b675','0065a372d4ff9d992848242290134b75']"


   condition:
      
      filesize > 65536 and filesize < 262144
      and hash.md5(0,16384) == "7b0c952a938813de62a56ad48eca7988"
}

