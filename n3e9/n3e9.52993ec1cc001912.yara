
rule n3e9_52993ec1cc001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.52993ec1cc001912"
     cluster="n3e9.52993ec1cc001912"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious adwaredealply"
     md5_hashes="['2fad8dd84eb8b0f38a118e860d245a9d','66b5a9fab54a035118cfaacd2526bb53','ba74c7fbb3e8a19a29f3bd9058e92c07']"

   strings:
      $hex_string = { 00720063006800050041007000720069006c0003004d006100790004004a0075006e00650004004a0075006c0079000600410075006700750073007400090053 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
