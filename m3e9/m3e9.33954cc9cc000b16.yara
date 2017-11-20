
rule m3e9_33954cc9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33954cc9cc000b16"
     cluster="m3e9.33954cc9cc000b16"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['1069df4d91995e0e94f023cedea2e99d','17e1a7b6e41b1bd4c9962621a73f0899','e55f2024649fde6eccb780e825e29efa']"

   strings:
      $hex_string = { 9fec3ed28838dedd767483255d93b9d56b680784127332a84ea33305ac7e973504dfafbfaf0ebecc95a03aadedfbdbe21f3dfae9e14002f2349c09b130c5b88d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
