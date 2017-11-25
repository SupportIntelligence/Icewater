
rule n3e9_131dbec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131dbec9c4000b12"
     cluster="n3e9.131dbec9c4000b12"
     cluster_size="304"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre otwycal patched"
     md5_hashes="['009c15a548063ee07571955570f5a1a6','0226b9b098aca55bf71ba42f8d498853','2897274a54a2a2fb59a250f02d5c5e64']"

   strings:
      $hex_string = { f2050e9fe48232b83988ee7ccbc5ec3efccc17d537d47d09f5948d9ce09250355f017b47559d8fa34251b630ff1c8a76ed568bb58ec6cd9d62771d0f639e3d2f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
