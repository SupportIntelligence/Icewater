
rule m3e9_31633947adbc4cd2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31633947adbc4cd2"
     cluster="m3e9.31633947adbc4cd2"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['0b4cdf099c653cdb441e4a289a746fce','acaafcd7849a6a044a532544a4bc9ff3','cb771d25468dcce7b894045307946a16']"

   strings:
      $hex_string = { e2f5e089f482945e05ec63ee59a3f1a083e4340b4ad0905946aac3564de1b314bfd909ce6d5540cc5a635fc24bd8123aace3615b3bed248c192edc71b0319c60 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
