
rule m2377_715f2008d9eb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.715f2008d9eb0932"
     cluster="m2377.715f2008d9eb0932"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0308411ed77cbf542af9fc609236df2e','12e68472ead87cf88cdc60a4bd110f74','df8e35c9ae3b72abecd698f5d152aa80']"

   strings:
      $hex_string = { 2043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e6420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
