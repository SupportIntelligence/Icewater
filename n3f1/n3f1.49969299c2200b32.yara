
rule n3f1_49969299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.49969299c2200b32"
     cluster="n3f1.49969299c2200b32"
     cluster_size="29"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos andr"
     md5_hashes="['0058f602a2a1a7487c398b5cc06e1592','0ecd80c1c16caec0fb21b97ef68364e1','998dbf11c7ba08da57358d819e8435da']"

   strings:
      $hex_string = { 10a0333ee1e772d67080759174468b085f002ce3c60735a796e5eafa6ab749be1f7ef1d31fd55a6bd1c01509d24e22639c0e64bdd876ad0511d4aa581b87e2f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
