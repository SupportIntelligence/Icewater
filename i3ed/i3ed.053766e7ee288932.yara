import "hash"

rule i3ed_053766e7ee288932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053766e7ee288932"
     cluster="i3ed.053766e7ee288932"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue generickdz"
     md5_hashes="['025ec1f8f03795867458ef3ca9a52b3b','16db9c0f03d7a0ebf66d20d75532c1b5','72987dda9af61594b06ef9822df6e41a']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "73238df589b72e3187ccc4625eb01234"
}

