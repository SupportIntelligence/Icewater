
rule n3ed_39857a16dba31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a16dba31932"
     cluster="n3ed.39857a16dba31932"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['2baff481c55ebb6dce7c5f9d214006e5','2c361981cfb03e9c1cec85f1c2705168','be69a4608aab0cbeb9b78ece16846217']"

   strings:
      $hex_string = { 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
