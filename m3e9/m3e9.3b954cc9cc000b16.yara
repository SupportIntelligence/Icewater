
rule m3e9_3b954cc9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3b954cc9cc000b16"
     cluster="m3e9.3b954cc9cc000b16"
     cluster_size="15"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['1ee385f835d8f29e7ae91e5dea2e4f9d','25349ec947efda0f2eb9260b83e5da55','f4bff31d66b8a4a8a24e7fc2a06b4cf1']"

   strings:
      $hex_string = { 9fec3ed28838dedd767483255d93b9d56b680784127332a84ea33305ac7e973504dfafbfaf0ebecc95a03aadedfbdbe21f3dfae9e14002f2349c09b130c5b88d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
