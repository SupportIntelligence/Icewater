
rule k3e9_193429e159b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193429e159b2f316"
     cluster="k3e9.193429e159b2f316"
     cluster_size="68"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore advml attribute"
     md5_hashes="['04f0c969a66f3872107f0697e9ccc148','0993c4946b3afb7f395a268137dd92fd','39c54cb90077fb940ecd101578e9db4c']"

   strings:
      $hex_string = { 30ce0ec8e5fbb6737c2c29f209d0beafa94c1cec04c0069664a037205e3b457942157f6655481371f0b37a4456febb77cf85a635f16ad1a58cb439e65c501410 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
