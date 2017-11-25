
rule m3e9_13a97905c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13a97905c0000932"
     cluster="m3e9.13a97905c0000932"
     cluster_size="50"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious filetour engine"
     md5_hashes="['00ce23bb863a17a9039e54f5413fa783','0e25d68d85cc79fca32799d39ac6be7b','7ebe595d1d374d2689ac1f55a7af543d']"

   strings:
      $hex_string = { b02df7daeb060ae474038ac4aa92508bdc33d2f7356c61400080c230881343490bc075ed0bc97fe94b8a03aa3bdc75f858c3e81cffffff8b550883fa127205ba }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
