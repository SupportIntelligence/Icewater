
rule n3ed_091fb0f9c92bdb32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9c92bdb32"
     cluster="n3ed.091fb0f9c92bdb32"
     cluster_size="1825"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['00432d6601073574aa6eca4c0eb35ce3','01976b8904423e523374a03cdeda1731','085decd8130e63b3d3ad10ad2ea064e3']"

   strings:
      $hex_string = { 3c3075040bc9eb022bc88d45d050ff75145157e8686b000083c4103bc37404881eeb588b45d4483945e00f9cc183f8fc7c2d3b45147d283acb740a8a074784c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
