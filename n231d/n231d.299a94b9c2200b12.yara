
rule n231d_299a94b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.299a94b9c2200b12"
     cluster="n231d.299a94b9c2200b12"
     cluster_size="187"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos bankbot hqwar"
     md5_hashes="['c2bba900ad1970ff435ee786abd9e4ceea758023','66254b5d4145653591bd312257ae34270a34edfb','7aaeb9a1acd35ce67cc2d96bf4e915f6bd55785b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.299a94b9c2200b12"

   strings:
      $hex_string = { 2afbe8a77c22ecd21c24b07e7bd61386153271811620f6494cf9a29abf41971d334df7baf539c3f83893a079d859d1f36894cf6650d5146764b53cb7084503ae }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
