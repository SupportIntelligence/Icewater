
rule n3e9_016493d1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.016493d1cc000932"
     cluster="n3e9.016493d1cc000932"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit kazy lebag"
     md5_hashes="['19096b65d3c2e319e4e87bfee0462df7','224e7190f2666c348149914f76c34a60','d7296bbc6160d2025987dae0b8d87c3c']"

   strings:
      $hex_string = { 63f6f985747d5eea616cae8d3ec0591a7cd527c6e7e8502d20f77e1b6222db70e0ac1530a05698cb76bdaa29b7c5be9db3b2cd13ef5a4c4375400c6989183307 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
