
rule m3e9_6214a69d9b230b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6214a69d9b230b14"
     cluster="m3e9.6214a69d9b230b14"
     cluster_size="738987"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ludbaruma regrun malicious"
     md5_hashes="['00000c7abe2f59f0773cc38df595e89a','0000209de1896b5458e480e3db12a1b5','0001c128ecb16cad247b1968782e7a7f']"

   strings:
      $hex_string = { b0895da0895d90750f683459420068f4664000e86b9ffeff8b35345942008d4de051568b06ff50143bc3dbe27d11bfc06840006a14575650e8409ffeffeb05bf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
