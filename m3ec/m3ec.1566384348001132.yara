
rule m3ec_1566384348001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.1566384348001132"
     cluster="m3ec.1566384348001132"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0465a08ab4a4f2201cb0a68dfe102642','067c1592f28b0ed5478be317ab1e5a26','63c82591441d532fb891cca4ae84b9b7']"

   strings:
      $hex_string = { 7f76058b7508eb2733d26a038bc65bf7f38b4f18894decd16dec8b55ec3bc2730eb8feffff7f2bc23bc877038d340a8365fc006a008d460150e807faffff8bd8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
