
rule m3e9_3a5a3699c6220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5a3699c6220b14"
     cluster="m3e9.3a5a3699c6220b14"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['2189d24c6198ce7b245203f5638c7540','abf90ae90db7e647853130c653d8d001','e00db3450e80edc65b5f7e2a0aaf71c6']"

   strings:
      $hex_string = { beb674f1ff0b357749297efdc48e95aaf2c84f2f90dc70f701e9c733ce45f6bac92341d7e6b7844812f989989725e400d939645f4b11a0a224eeab8e92f328b0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
