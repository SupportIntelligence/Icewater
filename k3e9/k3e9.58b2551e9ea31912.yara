
rule k3e9_58b2551e9ea31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.58b2551e9ea31912"
     cluster="k3e9.58b2551e9ea31912"
     cluster_size="522"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader kryptik"
     md5_hashes="['0057e25433c277bae63ee3c8bc305ea3','00f0d6a2d789d58d9c84cfd96e5c7c3c','0f83fcf45c47706698822dbf28503771']"

   strings:
      $hex_string = { 55557fffffff005555557777777705555555555555555555554004c054000000000100000000003c01510000000000000008004d0053002000530061006e0073 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
