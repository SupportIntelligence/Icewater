
rule m2377_109b3949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.109b3949c8000b12"
     cluster="m2377.109b3949c8000b12"
     cluster_size="10"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3d8b3d907188a2ac59fea4718111c565','55c5ea2b3baad66d40f7c3bf925c6c6e','ff609022733c577c3993ccfe1d1d528d']"

   strings:
      $hex_string = { 0098aed1cea058ccffe6c9e702280c3ea29ba4a1d7aa2f4e792086a88b3dcbc174ca124bdc28fe069aab779c712291e4d4b2b53c8e04f157d927829467539f05 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
