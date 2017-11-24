
rule j3ec_43cca699c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.43cca699c2200932"
     cluster="j3ec.43cca699c2200932"
     cluster_size="496"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector vhpli malicious"
     md5_hashes="['00998e19af8230fbe38451e7cda2b75f','010840a2630d20b08608dfcb37242022','0f44a119000ebcc431488e77432945d7']"

   strings:
      $hex_string = { 180305be15cd5b07088bf181c6f8d959070b8bf1c1e60481c6459b3c070702038b4500048bd58b0207020233c6058bf833fe97090203894500068bfd8bd08917 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
