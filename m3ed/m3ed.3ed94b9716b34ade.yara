
rule m3ed_3ed94b9716b34ade
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3ed94b9716b34ade"
     cluster="m3ed.3ed94b9716b34ade"
     cluster_size="3133"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious quchispy"
     md5_hashes="['00099df157407ce912e0eae59521c08f','0014a2da03fe63f6070c253c79d066aa','01581c8878b70bd47c97d866a1372cfc']"

   strings:
      $hex_string = { 7400d81bfcda79bdd70ed0847f1d00b74d8c7edd120f502880eda2c7f005234d91838d0137190013870e730705f50c766b000cf690090ca7ca468a37dcfddc50 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
