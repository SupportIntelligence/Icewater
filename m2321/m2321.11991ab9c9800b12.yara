
rule m2321_11991ab9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.11991ab9c9800b12"
     cluster="m2321.11991ab9c9800b12"
     cluster_size="20"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira bqcb nezlxz"
     md5_hashes="['0013751a5f37503bc9db90cf8c8b4266','00f2a653b7b592b9c4aed50e8deb30d4','c40a358206d0e667b80a17ec8e1148e7']"

   strings:
      $hex_string = { 69e4789e038c36ac6e6c83cbc66f9ce1633bb633161f8f51ec1539d2454ec55ea18e43537aabf5af42c0295b22581bcec89608ad12b7477bc11e71bc4dc29af0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
