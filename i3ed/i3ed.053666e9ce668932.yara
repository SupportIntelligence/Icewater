import "hash"

rule i3ed_053666e9ce668932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053666e9ce668932"
     cluster="i3ed.053666e9ce668932"
     cluster_size="151"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue generickdz accv"
     md5_hashes="['01eb8049219c79d3b37e992341bc2330','024e72bd89712a87044fb613fceebfcd','2eecbffc69c181fa2bf5a33d6c49fb5c']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "2ce7a14e612f014d2098e71f7d61298d"
}

