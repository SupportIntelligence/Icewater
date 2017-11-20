
rule j3ec_32bb280600001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.32bb280600001912"
     cluster="j3ec.32bb280600001912"
     cluster_size="4"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['33c8c3c3ae0affb86b630af5bcf53dec','3605f29512b71b1dca0a9872c893b3c4','fe21cbe84790be72669a1eb50d021eff']"

   strings:
      $hex_string = { aec1f278da9b3c77b1644bfc2717fdbe94ac8b3ed3d2f6d1d1e181d2f058c75ddd237d63e303a3f1506f4bd60d8f8e9736f48dec1a2e25f717b66d296ceab86b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
