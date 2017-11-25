
rule n3f7_4912a08bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.4912a08bc6220b12"
     cluster="n3f7.4912a08bc6220b12"
     cluster_size="78"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['052d01b8e06be636bd8f5a2451d33780','05439dcc2dec883ad682dc8adbd44140','3ea5e9035fbcc76c648b606ff8a04ea7']"

   strings:
      $hex_string = { 4c46e8a888e794bb202d6c656e66726965642070726f6a6563742d205b333436503136314d425d20444f574e4c4f4144204c494e4b533a20467265616b536861 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
