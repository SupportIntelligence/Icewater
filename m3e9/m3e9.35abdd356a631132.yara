
rule m3e9_35abdd356a631132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.35abdd356a631132"
     cluster="m3e9.35abdd356a631132"
     cluster_size="82"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot gepys injector"
     md5_hashes="['01d50dc94d1857a2d15b461d70fe8444','03279f041d00cb02708cbaae69b26575','50e6e18d9395cd66414dbc1d6cf1e5d4']"

   strings:
      $hex_string = { 2f47a1fc58ab38bb5d85cfdf4ed6801926dcccb36fe40d1694a2c788e8ca69ceed025a828b23dff5bc03063d5222c5ec3448555beee277bf8f762c9ea3533125 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
