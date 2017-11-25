
rule m3e9_36c66a49c0000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.36c66a49c0000b14"
     cluster="m3e9.36c66a49c0000b14"
     cluster_size="495"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob chir"
     md5_hashes="['01733785de6bfe4076708d70929ccb22','01d7310a961c61a79475f366638d0b49','06f328d288df2ccb922ee865ddf4443b']"

   strings:
      $hex_string = { 4fea627bafaa19c82b37252dbe65a1128a250f63a3f7541cf921c9d615f352ac6e433207fd8217f8e5676c0d51f6bdf152c7bde7c430fc203109881d95291a4d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
