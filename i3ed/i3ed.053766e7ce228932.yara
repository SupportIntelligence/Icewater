import "hash"

rule i3ed_053766e7ce228932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053766e7ce228932"
     cluster="i3ed.053766e7ce228932"
     cluster_size="232"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue symmi"
     md5_hashes="['009b4fcf83d67575f0fcc3822fb34cae','02e176c0d87be8fabd2814442312b807','11d7f87877f2b920280a9eba358c70b1']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "73238df589b72e3187ccc4625eb01234"
}

