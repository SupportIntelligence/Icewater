
rule n3e9_499eea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499eea48c0000b32"
     cluster="n3e9.499eea48c0000b32"
     cluster_size="2026"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod jadtre viking"
     md5_hashes="['0018c9da272995d2883b22a086ba5223','0037991fb72c8c51736411c0713c054e','068f88831aebedf0d4b2f58f74371972']"

   strings:
      $hex_string = { 8e1c4287842971304175ceb974f4df5cd798e4bc3be71da3226db726c863c6c00c60271278fe3e6c1f2ba88cba61d923e61096ae372c1e20060a3a4cbd2d435a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
