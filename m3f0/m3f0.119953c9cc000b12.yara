
rule m3f0_119953c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.119953c9cc000b12"
     cluster="m3f0.119953c9cc000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira bqcb miras"
     md5_hashes="['82b54cd3150205b7ac11f0d00756f442','a1ba8a42433d4dfb97656b6543d3013a','ee141f9963f564b9083e59c56541f5b0']"

   strings:
      $hex_string = { 69e4789e038c36ac6e6c83cbc66f9ce1633bb633161f8f51ec1539d2454ec55ea18e43537aabf5af42c0295b22581bcec89608ad12b7477bc11e71bc4dc29af0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
