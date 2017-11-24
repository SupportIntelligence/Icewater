
rule m2321_6197b6b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.6197b6b9caa00b12"
     cluster="m2321.6197b6b9caa00b12"
     cluster_size="34"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys shipup kryptik"
     md5_hashes="['07baf3c90ea54abf32e2200d593a6765','10e9218ec50cf0d465fcc8ddb9d3659e','6fed0a0aa6ba796c38d3641512d77e67']"

   strings:
      $hex_string = { d367cddac1200635a92b663e5837c22caa873139aca195e2304de1f5cffae4cb2778b429eead97110b54b9c07df9329e466de6488e5dfe4cbe453ddb7799c52e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
