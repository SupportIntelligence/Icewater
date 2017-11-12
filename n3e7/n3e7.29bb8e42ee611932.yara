
rule n3e7_29bb8e42ee611932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.29bb8e42ee611932"
     cluster="n3e7.29bb8e42ee611932"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="guagua porntool tool"
     md5_hashes="['9f0e3ab497abb7a87c3c2bcab33b6d8e','a2a084f369f8f74f20b21924f20f60f5','faf4bb44f04bccc73391d0ff4618b778']"

   strings:
      $hex_string = { 9e595ea1d3d10c4f1f0fc528e4348944fdfad964df4fe3090539086444cdd61a4948dbd9f344778fab8383a5212e047d7c3ba7e816447684d81b09a819aab2ad }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
