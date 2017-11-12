
rule k3e9_4c6d9cc1c8000532
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4c6d9cc1c8000532"
     cluster="k3e9.4c6d9cc1c8000532"
     cluster_size="396"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd upatre waski"
     md5_hashes="['00801dc5eb324b0c1511a06af18c30f3','041aa3cc3aa1d30df04aeec273d1b612','18a8d2b58da2b5e68dad2374bc6d5587']"

   strings:
      $hex_string = { 65744b6579626f6172645374617465000000004c6f616449636f6e410000005265676973746572436c6173734100000000005600000000000000560000000000 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
