
rule k3f7_4a1a9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.4a1a9cc1c4000b12"
     cluster="k3f7.4a1a9cc1c4000b12"
     cluster_size="1979"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['002ec7198bf766a3554227415ef4df3d','00618b69fb525de6a5bebe6d23f4846d','01b7abecbcc3c32e73eb1287dde58dbb']"

   strings:
      $hex_string = { 747970653d27746578742f6a617661736372697074273e0a46422e696e6974287b0a617070496420203a202731353139353638313838333438323034272c0a73 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
