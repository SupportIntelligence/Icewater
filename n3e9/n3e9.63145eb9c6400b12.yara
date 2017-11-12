
rule n3e9_63145eb9c6400b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.63145eb9c6400b12"
     cluster="n3e9.63145eb9c6400b12"
     cluster_size="82"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload xiazai advml"
     md5_hashes="['0972b583badb2941a5f8d71fa0177a96','11473e220c9f878ced8102bb8e958908','33877e2671630947e2b7a03b4a3803f7']"

   strings:
      $hex_string = { 0a3c67f53305a0861e536c50e6aa19a5999e0f9580631718ee357c9a86487e9de3a8291fc3de3db0fdb1c863455985ad6fe1fbc7f009d3828872a23f104cfce5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
