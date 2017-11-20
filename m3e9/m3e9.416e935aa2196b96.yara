
rule m3e9_416e935aa2196b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.416e935aa2196b96"
     cluster="m3e9.416e935aa2196b96"
     cluster_size="14"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis clickdownload downware"
     md5_hashes="['21ee0781ed35b57a720f584555eff37c','22d25edb84cdad19957adc8726ee23ff','f7623259d29628d816a23a5eed001667']"

   strings:
      $hex_string = { a0e43f75cac12da33a391321d38da6dd933e0dc7c0746864b1c5d452cb1f148172f2444c7fb985f2057840cd8e914602fa6fac112320bdc91d70808c7a5ab2bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
