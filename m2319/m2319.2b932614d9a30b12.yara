
rule m2319_2b932614d9a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b932614d9a30b12"
     cluster="m2319.2b932614d9a30b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['6dd7a0499306b166862cecea6fffba2e','aa58648674657ec2e7576ed0e5e33594','f29ccf85033c2b330f5170be12142fa1']"

   strings:
      $hex_string = { 6c6f6773706f742e63612f323031332f30372f66656c697a2d6469612d646f2d616d69676f2e68746d6c273e46454c495a2044494120444f20414d49474f213c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
