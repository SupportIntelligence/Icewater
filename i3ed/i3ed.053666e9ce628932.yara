import "hash"

rule i3ed_053666e9ce628932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053666e9ce628932"
     cluster="i3ed.053666e9ce628932"
     cluster_size="117"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue generickdz accv"
     md5_hashes="['01fc820ef50754d5cf86da7edbc9e26c','050b01e2f6f97743619e467fed77bb26','408d78a19817b64d01026c6ff68c31a4']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "2ce7a14e612f014d2098e71f7d61298d"
}

