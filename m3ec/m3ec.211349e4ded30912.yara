
rule m3ec_211349e4ded30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.211349e4ded30912"
     cluster="m3ec.211349e4ded30912"
     cluster_size="20"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hacktool kmsauto zusy"
     md5_hashes="['08c219503e9f98929f70857dedb2c65d','090061006046af3e2c067f8cb34fd807','dbd36a4e48177e38786ffe248a6c3d5c']"

   strings:
      $hex_string = { 757d48aceb33b20593dc55ef10c676d5db90e0066495c97ef307ee107017f21d136f56a1225c57b95e79af8037a66b87d91f4a209fb7e1674918b0f8e5087200 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
