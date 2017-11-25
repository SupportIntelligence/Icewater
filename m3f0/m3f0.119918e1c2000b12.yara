
rule m3f0_119918e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.119918e1c2000b12"
     cluster="m3f0.119918e1c2000b12"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira bqcb nezlxz"
     md5_hashes="['00420b598a6ed7e1b2c482741161ab23','2c08b24b0435d6fa554f36afcc44f498','eba7fd930aada004412b22495d3be7c1']"

   strings:
      $hex_string = { 69e4789e038c36ac6e6c83cbc66f9ce1633bb633161f8f51ec1539d2454ec55ea18e43537aabf5af42c0295b22581bcec89608ad12b7477bc11e71bc4dc29af0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
