
rule k3ec_35b121b9eb654932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.35b121b9eb654932"
     cluster="k3ec.35b121b9eb654932"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious engine heuristic"
     md5_hashes="['233439f49c97e558e11df115ddebbd02','53885fd9a6f401938db49556c5746de5','618c1b9904d779ac55871fd2f5b087aa']"

   strings:
      $hex_string = { 6450726976696c656765733e0d0a202020203c2f73656375726974793e0d0a20203c2f7472757374496e666f3e0d0a3c2f617373656d626c793e0d0a00000000 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
