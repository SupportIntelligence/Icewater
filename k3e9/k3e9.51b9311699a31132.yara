import "hash"

rule k3e9_51b9311699a31132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9311699a31132"
     cluster="k3e9.51b9311699a31132"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['2296a2938d8ae03e08882254e0fb1877','490697846dc42d4d268e77e2992ef05b','ef3175adc53b29e97330a4b0add78652']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,4096) == "be1070b2c2c331a2fbb604474784a677"
}

