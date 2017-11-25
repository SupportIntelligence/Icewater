
rule m3f7_3919304bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.3919304bc6200b12"
     cluster="m3f7.3919304bc6200b12"
     cluster_size="1195"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0065199e56f716140b96cd039288d621','00a6c7892b22e33fb0e89b23afb937af','02a7f7a17ef50422d983ad2ced5aa809']"

   strings:
      $hex_string = { 303030220d0a5365742046534f203d204372656174654f626a6563742822536372697074696e672e46696c6553797374656d4f626a65637422290d0a44726f70 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
