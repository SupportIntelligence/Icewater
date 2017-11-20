
rule m3e9_5216968be6600b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5216968be6600b12"
     cluster="m3e9.5216968be6600b12"
     cluster_size="624"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['0030f306bbb64773758e83b97172b7b5','004fe1824f80f4240119a9ad919c5ed8','16996dbc00a81f2f1159113c841e29a1']"

   strings:
      $hex_string = { 45c8508d4dcc518d55d0528d45d4506a08ff158011400083c424c745fc1e000000e82a6dfeffff15581040006817db4100eb3f8b4df083e10485c974098d4ddc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
