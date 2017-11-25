
rule m3f7_61bd684cd8bf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.61bd684cd8bf4912"
     cluster="m3f7.61bd684cd8bf4912"
     cluster_size="209"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0100570e2f710979ae348561f4acd5c1','04fe56bbe602e8d626fd1464047fe6d0','11ea90aeaf8e1c81b553c9eccc734dce']"

   strings:
      $hex_string = { 32423636433730413839394245444445413432444634303539324437304341313745363242304643353044374635343035423531333143323833383333363331 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
